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
    let bytes = harvest_common::to_cbor(plaintext).expect("encode plaintext");
    encrypt_bytes_seeded(
        &bytes,
        &plaintext.conversation_id,
        tag,
        aes_key,
        timestamp,
        nonce_seed,
    )
}

/// [`encrypt_message_seeded`] of any plaintext bytes: what a writer who
/// encodes their own message can send.
pub fn encrypt_bytes_seeded(
    bytes: &[u8],
    conversation_id: &harvest_common::mailbox::ConversationId,
    tag: &[u8; 32],
    aes_key: &[u8; 32],
    timestamp: DateTime<Utc>,
    nonce_seed: u64,
) -> harvest_common::mailbox::EncryptedMessage {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use aes_gcm::{Aes256Gcm, Nonce};
    let padded = harvest_common::mailbox::pad_to_bucket(bytes);
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&blake3::hash(&nonce_seed.to_le_bytes()).as_bytes()[..24]);
    let aad =
        harvest_common::mailbox::message_aad(conversation_id, tag.as_slice(), &timestamp, &nonce);
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
        conversation_id: conversation_id.clone(),
        sender_public_key: tag.to_vec(),
        ciphertext,
        timestamp,
        nonce,
    }
}

/// The instant-checkout ledger as the delegate stores it
/// (`delegates/harvest-delegate/src/auto_invoice.rs`, `Ledger`, `Sale`): a
/// crate-private type, mirrored field for field. A drift is caught where it is
/// used (a re-arm must read the seeded issued count back), not silently.
#[derive(serde::Serialize)]
struct Ledger {
    seen: Vec<[u8; 32]>,
    answered: Vec<[u8; 32]>,
    issued_at_ms: Vec<u64>,
    statuses: Vec<harvest_common::listing::ListingStatus>,
    sales: Vec<Sale>,
    settled: Vec<harvest_common::payment::OrderId>,
    oversold: Vec<Oversold>,
    gap_orders: Vec<(harvest_common::payment::OrderId, u32)>,
    gap_paid: Option<(u64, u32)>,
    capped: Option<(u64, String)>,
    retry_pending: bool,
}

#[derive(serde::Serialize)]
struct Sale {
    order: harvest_common::payment::OrderId,
    listing: harvest_common::listing::ListingId,
    quantity: u32,
    issued_at_ms: u64,
    anchor_height: u32,
    decremented: Option<u64>,
}

#[derive(serde::Serialize)]
struct Oversold {
    order: harvest_common::payment::OrderId,
    found_at_ms: u64,
}

fn id32(tag: u8, n: u32, i: usize) -> [u8; 32] {
    let mut b = [tag; 32];
    b[1..5].copy_from_slice(&n.to_le_bytes());
    b[5..13].copy_from_slice(&(i as u64).to_le_bytes());
    b
}

/// One arm's ledger with every list at its cap, `issued` invoices in the last
/// hour, and recent entries, so nothing is aged out on load.
pub fn full_ledger(
    arm: u32,
    now_ms: u64,
    issued: usize,
    caps: &crate::LedgerCaps,
) -> impl serde::Serialize {
    use harvest_common::listing::ListingId;
    use harvest_common::payment::OrderId;
    Ledger {
        seen: (0..caps.seen).map(|i| id32(0xA1, arm, i)).collect(),
        answered: (0..caps.answered).map(|i| id32(0xA2, arm, i)).collect(),
        issued_at_ms: (0..issued).map(|i| now_ms - 60_000 - i as u64).collect(),
        statuses: Vec::new(),
        sales: (0..caps.sales)
            .map(|i| Sale {
                order: OrderId(id32(0xA3, arm, i)),
                listing: ListingId(id32(0xA4, arm, i % 64)),
                quantity: 1,
                issued_at_ms: now_ms - 120_000,
                anchor_height: 250_000,
                decremented: None,
            })
            .collect(),
        settled: (0..caps.answered)
            .map(|i| OrderId(id32(0xA5, arm, i)))
            .collect(),
        oversold: Vec::new(),
        gap_orders: (0..caps.gap_orders)
            .map(|i| (OrderId(id32(0xA6, arm, i)), i as u32))
            .collect(),
        gap_paid: None,
        capped: None,
        retry_pending: false,
    }
}
