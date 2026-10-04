//! The reputation record at its caps (harvest#226).
//!
//! A record holds at most `MAX_COMPLAINTS` (146) complaints, one per paid
//! order of the store, and each complaint at most `MAX_COMPLAINT_BYTES`
//! (280 KiB) of CBOR. The count cap is derived as
//! `RECORD_BUDGET_BYTES / MAX_COMPLAINT_BYTES` so that it "holds even if
//! every complaint is the largest that verifies"; this fixture is that case,
//! about 40 MiB of state.
//!
//! # What makes a complaint as large and as costly as the contract allows
//!
//! Every complaint here is genuine: `Complaint::verify` accepts it, and the
//! held state is built by `ReputationStateV1::apply_delta`, which verifies
//! each one, then checked with `verify`. What the contract bounds, and where
//! each complaint sits against it:
//!
//! * **The seller's signed order** (`MAX_ORDER_ENVELOPE_BYTES`, 4 KiB, on the
//!   envelope and on the terms): every optional field filled, and as many
//!   trusted bridges as fit, the room the bound's own comment names ("dozens
//!   of bridges"). The envelope is the length that binds: 35 bridges give a
//!   4,069-byte envelope over 2,053 bytes of terms.
//! * **The payment evidence** (`MAX_PROOF_CLAIMS`, 32 distinct claims, and
//!   `MAX_PROOF_CLAIM_BYTES`, 256 KiB of encoded claims): 32 claims, the
//!   most a proof may carry. It is still a MINIMAL proof
//!   (`verify_minimal_proof`): the order is paid by 32 transactions of a
//!   32nd of its amount each, and the rest do not cover it without any one
//!   of them. Each claim's SPV proof carries as many following headers as
//!   the verifier accepts (`MAX_FOLLOWING_HEADERS`, 24) and the Merkle
//!   branch of a 16,384-transaction block (depth 14; 32 claims at
//!   `MAX_MERKLE_DEPTH`, 24, do not fit the byte budget), and each
//!   transaction has as many inputs as keep the 32 claims inside that
//!   budget: three, 516 bytes, for 259,572 bytes of claims.
//! * **The buyer's statement**: a genuine signature by the order's
//!   `buyer_receipt_key` over the exact envelope of its terms.
//!
//! Each complaint encodes to 270,457 to 271,719 bytes against the bound of
//! 286,720; the rest of the bound is the 16 KiB margin `MAX_COMPLAINT_BYTES`
//! adds for framing, which nothing genuine fills. The held record is
//! 39,592,445 bytes. Two costs scale with it: the bytes, which every call
//! decodes and `summarize`, `delta` and `apply_delta` re-encode per
//! complaint to digest it, and the claims, each an Ed25519 verification and
//! an SPV check, for every complaint, on every verification.
//!
//! An ordinary complaint is one claim of a few kilobytes. 32 payments per
//! order is not a buyer's behaviour, but the contract accepts it, and a
//! seller flooding its own record (the threat `MAX_COMPLAINTS` exists for)
//! can choose it: this is the record the contract's own bound admits.
//!
//! The record also carries the genuine Ghost Key owner certificate
//! (`tests/fixtures/ghostkey-certificate.pem`), which `validate_state`
//! checks on every call.
//!
//! # Determinism
//!
//! Keys come from [`super::signing_key`], every other byte from
//! [`super::bytes`], and Ed25519 signing is deterministic. The SPV headers
//! are mined at the easiest target the signet floor accepts
//! (`PowFloor::NONE`), a nonce search over deterministic input. No RSA key
//! or blind signature appears: the record has carried none since harvest#53
//! Phase C, and nothing here draws randomness.

use anyhow::{anyhow, bail, Result};
use ed25519_dalek::{Signer, SigningKey};
use freenet_bitcoin_common::spv::testing::{mine, sha256d_pub, EASIEST_BITS};
use freenet_bitcoin_common::spv::{
    merkle_root_from_branch, BlockHeader, MAX_FOLLOWING_HEADERS, MAX_MERKLE_DEPTH,
};
use freenet_bitcoin_common::{
    BitcoinNetwork, BlockAnchor, BlockHash, BridgeId, Claim, ClaimBody, OutPoint, SignedClaim,
    SignedTipEntry, SpvProof, TipEntryBody, Txid,
};
use harvest_common::feedback::FeedbackCategory;
use harvest_common::payment::{
    paid_height, AuthorizedOrder, Order, OrderId, OrderPaymentProof, OrderStatus,
    MAX_ORDER_ENVELOPE_BYTES, MAX_PROOF_CLAIMS, MAX_PROOF_CLAIM_BYTES,
};
use harvest_common::reputation::{
    Complaint, ComplaintTag, ComplaintTerms, ReputationParameters, ReputationStateV1,
    MAX_COMPLAINTS, MAX_COMPLAINT_BYTES,
};

use super::{array, bytes, cbor, now, signing_key, Case, Kind, Update};

/// A genuine Ghost Key certificate chained to Freenet's production master
/// key, as the contract's own tests and `tests/rehearsal` use.
const CERTIFICATE: &str = include_str!("../../../fixtures/ghostkey-certificate.pem");

/// The order's amount: what the 32 payments add up to.
const AMOUNT_SATS: u64 = 50_000;

/// The block every order is anchored at. Its payment window starts the
/// block after.
const ORDER_ANCHOR: u32 = 90;

/// The block every payment confirms at, and the bridge's tip when it said
/// so. With one required confirmation it is also each order's paid height.
const CONFIRMED_AT: u32 = 100;

/// The trusted bridges an order may name besides the one that signs: the
/// most that are tried before the envelope bound decides.
const MAX_EXTRA_BRIDGES: u64 = 64;

/// The Merkle branch every SPV proof carries: a block of 16,384
/// transactions, more than any real block holds. `MAX_MERKLE_DEPTH` (24)
/// is not used because 32 claims at that depth with 24 following headers do
/// not fit `MAX_PROOF_CLAIM_BYTES` even with a one-input transaction; the
/// claim count, which multiplies the signature checks, is kept at its cap
/// instead.
const MERKLE_DEPTH: usize = 14;
const _: () = assert!(MERKLE_DEPTH <= MAX_MERKLE_DEPTH);

/// One scriptSig as a P2PKH spend carries it: a DER signature and a
/// compressed public key.
const SCRIPT_SIG_BYTES: usize = 107;

struct Fx {
    store: SigningKey,
    bridge: SigningKey,
}

/// Sign `value` as the Ghost Key vault does for the Harvest web app: its
/// signature over the scoped payload (`tests/rehearsal`, `scoped_sign`).
fn scoped_sign<T: serde::Serialize>(key: &SigningKey, value: &T) -> Result<(Vec<u8>, Vec<u8>)> {
    let payload = harvest_common::to_cbor(value).map_err(|e| anyhow!(e))?;
    let scoped = harvest_common::to_cbor(&ghostkey_common::ScopedPayload {
        requestor: harvest_common::expected_harvest_requestor(),
        payload,
    })
    .map_err(|e| anyhow!(e))?;
    let signature = key.sign(&scoped).to_bytes().to_vec();
    Ok((scoped, signature))
}

/// A string of `len` characters for `label` and `i`, base58 like the
/// fingerprints and addresses it stands in for.
fn text(label: &str, i: u64, len: usize) -> String {
    let mut s = bs58::encode(bytes(label, i, len)).into_string();
    s.truncate(len);
    s
}

impl Fx {
    /// Order `i` of record `label`, naming `buyer` as its buyer, with every
    /// optional field filled and `extra` further trusted bridges.
    fn order_with(&self, label: &str, i: u64, buyer: &SigningKey, extra: u64) -> Order {
        let mut trusted_bridges = vec![BridgeId(self.bridge.verifying_key().to_bytes())];
        trusted_bridges.extend((0..extra).map(|j| {
            BridgeId(
                signing_key("reputation/other-bridge", j)
                    .verifying_key()
                    .to_bytes(),
            )
        }));
        // A P2WPKH output script, and the 42-character signet address that
        // spells it.
        let mut payment_script_pubkey = vec![0x00, 0x14];
        payment_script_pubkey.extend(bytes(&format!("{label}/script"), i, 20));
        Order {
            request_id: Some(array(&format!("{label}/request"), i)),
            id: OrderId([0u8; 32]),
            buyer_fingerprint: text(&format!("{label}/buyer-fingerprint"), i, 32),
            seller_fingerprint: text("reputation/seller-fingerprint", 0, 32),
            amount_sats: AMOUNT_SATS,
            network: BitcoinNetwork::Signet,
            payment_script_pubkey,
            payment_hash: None,
            payment_address: format!("tb1q{}", text(&format!("{label}/address"), i, 38)),
            required_confirmations: 1,
            trusted_bridges,
            bitcoin_address_code_hash: Some(array("reputation/address-code-hash", 0)),
            anchor: Some(BlockAnchor {
                height: ORDER_ANCHOR,
                hash: BlockHash(array(&format!("{label}/anchor"), i)),
            }),
            order_binding: Some(array(&format!("{label}/binding"), i)),
            listing_tag: Some(array(&format!("{label}/listing-tag"), i)),
            buyer_receipt_key: Some(buyer.verifying_key().to_bytes()),
            created_at: now() - chrono::Duration::days(30) + chrono::Duration::seconds(i as i64),
        }
        .with_derived_id()
    }

    /// [`Self::order_with`] with as many bridges as keep the seller's signed
    /// envelope inside `MAX_ORDER_ENVELOPE_BYTES`, and its signature.
    fn signed_order(
        &self,
        label: &str,
        i: u64,
        buyer: &SigningKey,
    ) -> Result<(Order, Vec<u8>, Vec<u8>)> {
        for extra in (0..=MAX_EXTRA_BRIDGES).rev() {
            let order = self.order_with(label, i, buyer, extra);
            let (envelope, signature) = scoped_sign(&self.store, &order)?;
            if envelope.len() <= MAX_ORDER_ENVELOPE_BYTES {
                if extra == MAX_EXTRA_BRIDGES {
                    bail!("raise MAX_EXTRA_BRIDGES: the envelope bound did not bind");
                }
                return Ok((order, envelope, signature));
            }
        }
        bail!("an order with one bridge does not fit MAX_ORDER_ENVELOPE_BYTES")
    }

    /// A transaction paying `value` to `script` as its output 0, with change,
    /// spending `inputs` P2PKH-shaped inputs.
    fn transaction(
        label: &str,
        i: u64,
        k: u64,
        value: u64,
        script: &[u8],
        inputs: usize,
    ) -> Vec<u8> {
        let seed = format!("{label}/tx/{k}");
        let mut t = 2u32.to_le_bytes().to_vec();
        assert!(inputs > 0 && inputs < 0xfd, "a one-byte input count");
        t.push(inputs as u8);
        for n in 0..inputs {
            let n = n as u64;
            t.extend(bytes(&format!("{seed}/prevout"), i * 1_000 + n, 32));
            t.extend_from_slice(&(n as u32).to_le_bytes());
            t.push(SCRIPT_SIG_BYTES as u8);
            t.extend(bytes(
                &format!("{seed}/script-sig"),
                i * 1_000 + n,
                SCRIPT_SIG_BYTES,
            ));
            t.extend_from_slice(&0xffff_fffdu32.to_le_bytes());
        }
        t.push(2);
        t.extend_from_slice(&value.to_le_bytes());
        t.push(script.len() as u8);
        t.extend_from_slice(script);
        t.extend_from_slice(&(100_000 + i).to_le_bytes());
        t.push(22);
        t.extend_from_slice(&[0x00, 0x14]);
        t.extend(bytes(&format!("{seed}/change"), i, 20));
        t.extend_from_slice(&0u32.to_le_bytes());
        t
    }

    /// Payment `k` of order `i`: a bridge-signed claim that a transaction
    /// paying `value` to the order's script confirmed at [`CONFIRMED_AT`],
    /// with an SPV proof as deep as the verifier accepts.
    fn claim(
        &self,
        label: &str,
        i: u64,
        k: u64,
        order: &Order,
        value: u64,
        inputs: usize,
    ) -> SignedClaim {
        let raw_tx = Self::transaction(label, i, k, value, &order.payment_script_pubkey, inputs);
        let txid = Txid(sha256d_pub(&raw_tx));
        let seed = format!("{label}/spv/{k}");
        let merkle_branch: Vec<[u8; 32]> = (0..MERKLE_DEPTH as u64)
            .map(|d| array(&format!("{seed}/branch/{d}"), i))
            .collect();
        let tx_index =
            u32::from_le_bytes(array(&format!("{seed}/index"), i)) & ((1 << MERKLE_DEPTH) - 1);
        let root = merkle_root_from_branch(&txid, &merkle_branch, tx_index).expect("in bounds");
        let header = mine(
            array(&format!("{seed}/prev"), i),
            root,
            1_700_000_000,
            EASIEST_BITS,
        );
        let mut following: Vec<BlockHeader> = Vec::with_capacity(MAX_FOLLOWING_HEADERS);
        let mut last = header;
        for h in 0..MAX_FOLLOWING_HEADERS as u64 {
            let next = mine(
                sha256d_pub(&last.0),
                array(&format!("{seed}/root/{h}"), i),
                1_700_000_000 + 600 * (h as u32 + 1),
                EASIEST_BITS,
            );
            following.push(next);
            last = next;
        }
        let anchor = BlockAnchor {
            height: CONFIRMED_AT,
            hash: BlockHash(sha256d_pub(&header.0)),
        };
        SignedClaim::sign(
            &self.bridge,
            &ClaimBody {
                script_id: order.bitcoin_params().script_id(),
                network: order.network,
                as_of: anchor,
                claim: Claim::ConfirmedOutput {
                    outpoint: OutPoint { txid, vout: 0 },
                    value_sats: value,
                    anchor,
                    spv: SpvProof {
                        raw_tx,
                        merkle_branch,
                        tx_index,
                        header,
                        following_headers: following,
                    },
                },
            },
        )
        .expect("sign claim")
    }

    /// The largest claim for payment `k` that keeps 32 of them inside
    /// `MAX_PROOF_CLAIM_BYTES`: the most inputs that fit its share.
    fn largest_claim(
        &self,
        label: &str,
        i: u64,
        k: u64,
        order: &Order,
        value: u64,
    ) -> Result<SignedClaim> {
        let share = MAX_PROOF_CLAIM_BYTES / MAX_PROOF_CLAIMS;
        let cost = |c: &SignedClaim| cbor(c).len();
        let mut inputs = 1;
        let mut best = self.claim(label, i, k, order, value, inputs);
        if cost(&best) > share {
            bail!(
                "a one-input claim is {} bytes, over its share {share}",
                cost(&best)
            );
        }
        loop {
            let next = self.claim(label, i, k, order, value, inputs + 1);
            if cost(&next) > share {
                return Ok(best);
            }
            best = next;
            inputs += 1;
        }
    }

    /// Complaint `i` of record `label`, dated `distance` blocks after its
    /// payment, at every bound described in the module docs.
    fn complaint(&self, label: &str, i: u64, distance: u32) -> Result<Complaint> {
        let buyer = signing_key(&format!("{label}/buyer"), i);
        let (order, scoped_payload, signature) = self.signed_order(label, i, &buyer)?;
        // 32 payments of a 32nd each, rounded up: together they cover the
        // amount, and without any one of them the rest do not.
        let k_count = MAX_PROOF_CLAIMS as u64;
        let value = AMOUNT_SATS.div_ceil(k_count);
        let claims = (0..k_count)
            .map(|k| self.largest_claim(label, i, k, &order, value))
            .collect::<Result<Vec<_>>>()?;
        let tip = SignedTipEntry::sign(
            &self.bridge,
            &TipEntryBody {
                network: order.network,
                anchor: BlockAnchor {
                    height: CONFIRMED_AT,
                    hash: BlockHash(array("reputation/tip", 0)),
                },
                prev_hash: BlockHash(array("reputation/tip-prev", 0)),
                block_time: 1_700_000_000,
                tx_count: 3_000,
                median_time: 1_699_999_000,
            },
        )
        .map_err(|e| anyhow!(e))?;
        let order = AuthorizedOrder {
            order,
            scoped_payload,
            signature,
            status: OrderStatus::Paid,
            payment_proof: Some(OrderPaymentProof::on_chain(claims, tip)),
            status_scoped_payload: None,
            status_signature: None,
        };
        let paid_at =
            paid_height(&order).ok_or_else(|| anyhow!("the fixture order is not paid"))?;
        let terms = ComplaintTerms {
            tag: ComplaintTag::HarvestComplaintV1,
            order_id: order.order.id.clone(),
            category: FeedbackCategory::ALL[i as usize % FeedbackCategory::ALL.len()].clone(),
            block_height: paid_at + distance,
            paid_height: paid_at,
        };
        let (scoped_payload, buyer_signature) = scoped_sign(&buyer, &terms)?;
        let complaint = Complaint {
            order,
            category: terms.category,
            block_height: terms.block_height,
            paid_height: terms.paid_height,
            scoped_payload,
            buyer_signature,
        };
        complaint
            .verify(&self.store.verifying_key())
            .map_err(|e| anyhow!("the fixture complaint does not verify: {e}"))?;
        Ok(complaint)
    }

    /// A record at its caps: `MAX_COMPLAINTS` complaints, dated
    /// `offset + 1`, `offset + 3`, ... blocks after their payments, so two
    /// records built with offsets 0 and 1 interleave and a merge of the two
    /// keeps the nearer half of each.
    fn at_cap(&self, label: &str, offset: u32) -> Result<ReputationStateV1> {
        let params = ReputationParameters::new(self.store.verifying_key());
        let complaints = (0..MAX_COMPLAINTS as u64)
            .map(|i| self.complaint(label, i, offset + 1 + 2 * i as u32))
            .collect::<Result<Vec<_>>>()?;
        let mut state = ReputationStateV1 {
            owner_certificate_pem: CERTIFICATE.into(),
            complaints: Vec::new(),
        };
        state
            .apply_delta(&params, &Some(complaints))
            .map_err(|e| anyhow!("{e}"))?;
        state
            .verify(&params)
            .map_err(|e| anyhow!("the reputation fixture fails verify: {e}"))?;
        check_at_cap(&state)?;
        Ok(state)
    }
}

/// The record is at the count cap, and every complaint at the claim cap and
/// within 10% of the byte bound.
fn check_at_cap(state: &ReputationStateV1) -> Result<()> {
    if state.complaints.len() != MAX_COMPLAINTS {
        bail!(
            "the reputation fixture holds {} complaints, not {MAX_COMPLAINTS}",
            state.complaints.len()
        );
    }
    for c in &state.complaints {
        let size = cbor(c).len();
        let claims = match &c.order.payment_proof {
            Some(OrderPaymentProof::OnChain(p)) => p.claims.len(),
            _ => 0,
        };
        if claims != MAX_PROOF_CLAIMS
            || !(MAX_COMPLAINT_BYTES * 9 / 10..=MAX_COMPLAINT_BYTES).contains(&size)
        {
            bail!(
                "a fixture complaint is not at its caps: {claims} claims, {size} bytes \
                 (bound {MAX_COMPLAINT_BYTES})"
            );
        }
    }
    Ok(())
}

pub fn cases() -> Result<Vec<Case>> {
    let fx = Fx {
        store: signing_key("reputation/store", 0),
        bridge: signing_key("reputation/bridge", 0),
    };
    let parameters = cbor(&ReputationParameters::new(fx.store.verifying_key()));
    let held = fx.at_cap("reputation/held", 0)?;
    let held_bytes = cbor(&held);

    // (a) One buyer's complaint, dated at its payment: nearer than every
    // complaint held, so the cap keeps it and drops the farthest.
    let one: Vec<Complaint> = vec![fx.complaint("reputation/new", 0, 0)?];

    // (b) A second, different record at its caps, as a PUT, a resync or the
    // migration's fold delivers it. Its complaints interleave the held
    // ones by distance, so the merge keeps 73 of each: still at the cap,
    // and not the held state.
    let other = fx.at_cap("reputation/other", 1)?;

    Ok(vec![
        Case {
            kind: Kind::Reputation,
            name: "146 at caps + one-complaint delta".into(),
            parameters: parameters.clone(),
            held: held_bytes.clone(),
            update: Update::Delta(cbor(&one)),
        },
        Case {
            kind: Kind::Reputation,
            name: "146 at caps + another 146-at-caps state".into(),
            parameters,
            held: held_bytes,
            update: Update::State(cbor(&other)),
        },
    ])
}
