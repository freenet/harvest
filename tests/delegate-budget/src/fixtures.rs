//! Inputs the Harvest web app (and the Ghost Key vault) would supply, built
//! so every signature and proof verifies for real. A fixture that only looks
//! right would measure a refusal path -- which is cheap -- instead of the
//! handler's real work, and the budget would pass for the wrong reason.

use chrono::{DateTime, TimeZone, Utc};
use ed25519_dalek::{Signer, SigningKey};
use freenet_bitcoin_common::spv::testing::payment_proof;
use freenet_bitcoin_common::{
    BitcoinNetwork, BlockAnchor, BlockHash, BridgeId, Claim, ClaimBody, OutPoint, SignedClaim,
    SignedTipEntry, TipEntryBody,
};
use harvest_common::payment::{AuthorizedOrder, Order, OrderId, OrderPaymentProof, OrderStatus};

pub fn ts(secs: i64) -> DateTime<Utc> {
    Utc.timestamp_opt(secs, 0).unwrap()
}

/// What the Ghost Key vault answers for `SignMessage { message }` from the
/// Harvest web app: its signature over the scoped payload
/// (`delegates/harvest-delegate/src/store_keys.rs` tests, `vault_sign`).
pub fn vault_sign(key: &SigningKey, message: Vec<u8>) -> (Vec<u8>, Vec<u8>) {
    let scoped = ghostkey_common::to_cbor(&ghostkey_common::ScopedPayload {
        requestor: harvest_common::expected_harvest_requestor(),
        payload: message,
    })
    .expect("encode scoped payload");
    let sig = key.sign(&scoped).to_bytes().to_vec();
    (scoped, sig)
}

/// Sign a value the way the ghostkey delegate does (`tests/rehearsal`,
/// `scoped_sign`).
fn scoped_sign<T: serde::Serialize>(sk: &SigningKey, data: &T) -> (Vec<u8>, Vec<u8>) {
    let payload = harvest_common::to_cbor(data).expect("encode payload");
    vault_sign(sk, payload)
}

pub struct OrderFx {
    pub seller: SigningKey,
    pub bridge: SigningKey,
}

impl OrderFx {
    /// Order `n`, naming `buyer_receipt_key` as its buyer. Shaped as
    /// `tests/rehearsal`'s `ComplaintFx::order`: anchored, bridged, on-chain,
    /// so a complaint about it could be filed (`complaint_preconditions`).
    pub fn order(&self, n: u32, buyer_receipt_key: [u8; 32]) -> Order {
        let [a, b, c, d] = n.to_be_bytes();
        Order {
            request_id: None,
            id: OrderId([0u8; 32]),
            buyer_fingerprint: format!("budget-buyer-{n}"),
            seller_fingerprint: "budget-seller-fp".into(),
            amount_sats: 50_000,
            network: BitcoinNetwork::Signet,
            payment_script_pubkey: vec![0x00, 0x14, a, b, c, d],
            payment_hash: None,
            payment_address: "tb1qbudget".into(),
            required_confirmations: 1,
            trusted_bridges: vec![BridgeId(self.bridge.verifying_key().to_bytes())],
            bitcoin_address_code_hash: None,
            anchor: Some(BlockAnchor {
                height: 90,
                hash: BlockHash([3u8; 32]),
            }),
            order_binding: None,
            listing_tag: None,
            buyer_receipt_key: Some(buyer_receipt_key),
            created_at: ts(1_700_000_000 + i64::from(n)),
        }
        .with_derived_id()
    }

    /// The order at `Paid`, with a genuine SPV proof confirming at 100.
    pub fn paid(&self, order: Order) -> AuthorizedOrder {
        let (spv, txid, block_hash) = payment_proof(
            &order.payment_script_pubkey,
            order.amount_sats,
            1,
            [1u8; 32],
        );
        let anchor = BlockAnchor {
            height: 100,
            hash: block_hash,
        };
        let claim = SignedClaim::sign(
            &self.bridge,
            &ClaimBody {
                script_id: order.bitcoin_params().script_id(),
                network: order.network,
                as_of: anchor,
                claim: Claim::ConfirmedOutput {
                    outpoint: OutPoint { txid, vout: 0 },
                    value_sats: order.amount_sats,
                    anchor,
                    spv,
                },
            },
        )
        .expect("sign claim");
        let tip = SignedTipEntry::sign(
            &self.bridge,
            &TipEntryBody {
                network: order.network,
                anchor: BlockAnchor {
                    height: 100,
                    hash: BlockHash([9u8; 32]),
                },
                prev_hash: BlockHash([8u8; 32]),
                block_time: 1_700_000_000,
                tx_count: 1,
                median_time: 1_700_000_000,
            },
        )
        .expect("sign tip");
        let proof = OrderPaymentProof::on_chain(vec![claim], tip);
        let (scoped_payload, signature) = scoped_sign(&self.seller, &order);
        let rec = AuthorizedOrder {
            order,
            scoped_payload,
            signature,
            status: OrderStatus::Paid,
            payment_proof: Some(proof),
            status_scoped_payload: None,
            status_signature: None,
        };
        rec.verify(&self.seller.verifying_key())
            .expect("fixture order verifies");
        rec
    }
}

/// The BIP-84 account key for the specification's own test mnemonic,
/// re-encoded under the test-network version so it stands in for a seller's
/// signet wallet export (`delegates/harvest-delegate/src/bitcoin.rs` tests,
/// `vpub_with_chain_code`). `xor` perturbs the chain code: a different wallet.
pub fn signet_vpub(xor: u8) -> String {
    let mut bytes = bs58::decode(
        "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs",
    )
    .with_check(None)
    .into_vec()
    .expect("the BIP-84 vector must decode");
    bytes[..4].copy_from_slice(&0x045f_1cf6u32.to_be_bytes());
    bytes[13] ^= xor;
    bs58::encode(bytes).with_check().into_string()
}

/// `harvest_common::sealed::encrypt_message`, with the mailbox nonce taken
/// from `nonce_seed` instead of the OS RNG. Same padding, same associated
/// data, same cipher: the delegate cannot tell the difference, and the run
/// stays reproducible to the unit of fuel (a random nonce changes each
/// entry's digest, so the order the delegate walks them in, and the fuel).
pub fn encrypt_message_seeded(
    plaintext: &harvest_common::sealed::PlaintextMessage,
    tag: &[u8; 32],
    aes_key: &[u8; 32],
    timestamp: DateTime<Utc>,
    nonce_seed: u64,
) -> harvest_common::mailbox::EncryptedMessage {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use aes_gcm::{Aes256Gcm, Nonce};
    let bytes = harvest_common::to_cbor(plaintext).expect("encode plaintext");
    let padded = harvest_common::mailbox::pad_to_bucket(&bytes);
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&blake3::hash(&nonce_seed.to_le_bytes()).as_bytes()[..24]);
    let aad = harvest_common::mailbox::message_aad(
        &plaintext.conversation_id,
        tag.as_slice(),
        &timestamp,
        &nonce,
    );
    let ciphertext = Aes256Gcm::new_from_slice(aes_key)
        .expect("32-byte key")
        .encrypt(
            Nonce::from_slice(&nonce[..12]),
            Payload {
                msg: padded.as_ref(),
                aad: &aad,
            },
        )
        .expect("encrypt");
    harvest_common::mailbox::EncryptedMessage {
        conversation_id: plaintext.conversation_id.clone(),
        sender_public_key: tag.to_vec(),
        ciphertext,
        timestamp,
        nonce,
    }
}
