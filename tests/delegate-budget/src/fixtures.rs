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

    /// [`Self::order`] paying to `script`, created a minute ago rather than in
    /// 2023, as a busy store's recent orders are.
    pub fn order_on(&self, n: u32, script: Vec<u8>) -> Order {
        let mut order = self.order(n, [0x5B; 32]);
        order.payment_script_pubkey = script;
        order.created_at = ts(1_790_000_000 - 60);
        order.with_derived_id()
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
/// crate-private type, mirrored field for field. Most of its fields are
/// `serde(default)`, so a drifted mirror would still decode: the scenario
/// compares this mirror's field names with a ledger the delegate wrote
/// (`same_fields`), and a re-arm must read the seeded issued count back.
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

/// One arm's ledger with every list at its cap (`statuses` and `oversold`
/// share `STATUSES_CAP`), `issued` invoices in the last
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
        // A status per listing the sales name, each still waiting for the
        // store to show it.
        statuses: (0..caps.statuses)
            .map(|i| harvest_common::listing::ListingStatus {
                listing: ListingId(id32(0xA4, arm, i)),
                revision: 1_000 + i as u64,
                availability: harvest_common::listing::ListingAvailability::Available {
                    quantity: Some(1_000),
                },
            })
            .collect(),
        sales: (0..caps.sales)
            .map(|i| Sale {
                order: OrderId(id32(0xA3, arm, i)),
                listing: ListingId(id32(0xA4, arm, i % caps.statuses)),
                quantity: 1,
                issued_at_ms: now_ms - 120_000,
                anchor_height: 250_000,
                decremented: None,
            })
            .collect(),
        settled: (0..caps.answered)
            .map(|i| OrderId(id32(0xA5, arm, i)))
            .collect(),
        // Found a minute ago: shown for `OVERSOLD_SHOWN_MS`, so none ages out.
        oversold: (0..caps.statuses)
            .map(|i| Oversold {
                order: OrderId(id32(0xA7, arm, i)),
                found_at_ms: now_ms - 60_000,
            })
            .collect(),
        gap_orders: (0..caps.gap_orders)
            .map(|i| (OrderId(id32(0xA6, arm, i)), i as u32))
            .collect(),
        gap_paid: None,
        capped: None,
        retry_pending: false,
    }
}

/// A byte string CBOR-encoded as one (`serialize_bytes`), as
/// `freenet_bitcoin_inbox::ByteBuf` encodes, rather than as an array of
/// integers, which is how a plain `Vec<u8>` encodes.
struct Bytes(Vec<u8>);

impl serde::Serialize for Bytes {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(&self.0)
    }
}

/// `freenet_bitcoin_inbox::Delegation`.
#[derive(serde::Serialize)]
struct Delegation {
    scoped_payload: Bytes,
    signature: Bytes,
}

/// `freenet_bitcoin_inbox::DelegationBody`. Its `watch_key` is a
/// `WatchKeyId`, which encodes as `BridgeId` does (32 bytes, as a byte
/// string: `impl_bytes32_serde!`).
#[derive(serde::Serialize)]
struct DelegationBody {
    bridge: BridgeId,
    watch_key: BridgeId,
    issued_mainnet_height: u32,
    expires_mainnet_height: Option<u32>,
}

/// `freenet_bitcoin_inbox::DELEGATION_DOMAIN`: the prefix of what the Ghost
/// Key signs for a delegation.
const DELEGATION_DOMAIN: &[u8] = b"freenet-bitcoin/inbox-watch-delegation/v1\0";

/// A watch delegation as the Harvest delegate holds it
/// (`delegates/harvest-delegate/src/watch_delegation.rs`, `Held`, `Watched`): a
/// crate-private type, mirrored field for field, as [`Ledger`] is. The
/// scenario compares this mirror's field names (and a watch's) with a
/// delegation the delegate rewrote (`same_fields`); each status must also
/// count the delegation's watches, and the wake-up must read for it.
#[derive(serde::Serialize)]
struct Held {
    network: BitcoinNetwork,
    bridge: BridgeId,
    ghostkey: [u8; 32],
    certificate_pem: String,
    delegation: Delegation,
    issued_mainnet_height: u32,
    inbox_contract_id: [u8; 32],
    ui_made_at_ms: u64,
    own_made_at_ms: u64,
    outstanding: Option<()>,
    unconfirmed: Option<()>,
    watched: Vec<Watched>,
    failures: u32,
    last_failure_ms: Option<u64>,
    last_read_ms: u64,
    last_probe_ms: Option<u64>,
    canary: Option<()>,
    canary_next: u32,
    canary_tries: u32,
    defer_until_ms: Option<u64>,
    subscribed: Vec<([u8; 32], u64)>,
    subscribing: Vec<[u8; 32]>,
    ever_subscribed: Vec<[u8; 32]>,
}

#[derive(serde::Serialize)]
struct Watched {
    script: Vec<u8>,
    until_height: u32,
    canary: Vec<u8>,
    canary_contract: [u8; 32],
    canary_index: u32,
}

/// The delegation caps a seeded delegation is filled to.
pub struct DelegationCaps {
    pub watched: usize,
    pub subscribed: usize,
    pub ever_subscribed: usize,
}

/// A P2WPKH-shaped script no wallet here derives.
fn script(tag: u8, n: u32, i: usize) -> Vec<u8> {
    let mut s = vec![0x00, 0x14];
    s.extend_from_slice(&id32(tag, n, i)[..20]);
    s
}

/// The `n`th watch delegation, for `bridge`, held at its caps: `caps.watched`
/// confirmed watches that all count for an invoice issued now, the
/// delegate's next addresses (`pool`) last (the newest, as requests add
/// them), with older addresses before them.
///
/// What makes a watch count (`watch_delegation::covers`, `vouched`): its
/// horizon is at least `WATCH_NEEDED_BLOCKS` past the tip, and its canary
/// can still vouch for it: an index past the pool (the counter plus
/// `MAX_UPCOMING_ADDRESSES`) and a script no arm names. Each horizon is
/// `until_height`, which the caller puts short of the renewal margin, so the
/// wake-up also finds the delegation due a refill and goes on to choose a
/// canary: its longest path.
///
/// The delegation is genuine (the Ghost Key's signature over the body naming
/// `bridge` and `watch_key`, as the vault signs it); the certificate is the
/// repository's fixture. Neither is checked on the paths measured with it
/// (only `SetWatchDelegation` and sending a request check them), so they are
/// here for their size.
#[allow(clippy::too_many_arguments)]
pub fn full_delegation(
    n: u32,
    bridge: BridgeId,
    ghost: &SigningKey,
    watch_key: [u8; 32],
    pool: &[Vec<u8>],
    until_height: u32,
    now_ms: u64,
    caps: &DelegationCaps,
) -> impl serde::Serialize {
    let issued = 900_000;
    let mut payload = DELEGATION_DOMAIN.to_vec();
    payload.extend(
        freenet_bitcoin_common::to_cbor(&DelegationBody {
            bridge,
            watch_key: BridgeId(watch_key),
            issued_mainnet_height: issued,
            expires_mainnet_height: None,
        })
        .expect("encode delegation body"),
    );
    let (scoped, signature) = vault_sign(ghost, payload);
    // Past any pool and any arm's addresses, as `next_canary` chooses them.
    let canary_base = 1_000 + n * caps.watched as u32;
    let older = caps.watched.saturating_sub(pool.len());
    let scripts = (0..older)
        .map(|i| script(0xB0, n, i))
        .chain(pool.iter().cloned());
    Held {
        network: BitcoinNetwork::Signet,
        bridge,
        ghostkey: ghost.verifying_key().to_bytes(),
        certificate_pem: include_str!("../../fixtures/ghostkey-certificate.pem").into(),
        delegation: Delegation {
            scoped_payload: Bytes(scoped),
            signature: Bytes(signature),
        },
        issued_mainnet_height: issued,
        inbox_contract_id: id32(0xB1, n, 0),
        ui_made_at_ms: now_ms - 3_600_000,
        own_made_at_ms: now_ms - 3_600_000,
        outstanding: None,
        unconfirmed: None,
        watched: scripts
            .take(caps.watched)
            .enumerate()
            .map(|(i, script_pubkey)| Watched {
                script: script_pubkey,
                until_height,
                canary: script(0xB2, n, i),
                canary_contract: id32(0xB3, n, i),
                canary_index: canary_base + i as u32,
            })
            .collect(),
        failures: 0,
        last_failure_ms: None,
        // Distinct, so which delegation a wake-up reads is fixed.
        last_read_ms: now_ms - 3_600_000 - u64::from(n),
        // Probed just now: the wake-up goes past the probe to the refill.
        last_probe_ms: Some(now_ms),
        canary: None,
        canary_next: canary_base + caps.watched as u32,
        canary_tries: 0,
        defer_until_ms: None,
        subscribed: (0..caps.subscribed)
            .map(|i| (id32(0xB4, n, i), now_ms - 3_600_000))
            .collect(),
        subscribing: Vec::new(),
        ever_subscribed: (0..caps.ever_subscribed)
            .map(|i| id32(0xB5, n, i))
            .collect(),
    }
}
