//! The store at its caps (harvest#226).
//!
//! What `harvest_common::store` bounds, and what this fixture puts there:
//!
//! * **Orders: [`MAX_ORDERS`] (256)**, every one `Paid` with a genuine SPV
//!   payment proof, the status whose `verify` costs the most (the seller's
//!   signature on the terms, then the bridge's signed tip, the bridge's
//!   signed claim and the SPV proof inside it). Each is an instant-checkout
//!   answer, so every optional field is filled (request id, binding, listing
//!   tag, buyer receipt key, anchor, address-contract hash). The proof is the
//!   one the UI publishes (`minimal_on_chain_proof`, one claim) for a
//!   two-output transaction in a block of a few thousand, so its Merkle
//!   branch is 12 hashes deep. `MAX_PROOF_CLAIM_BYTES` (256 KiB a proof) is
//!   NOT filled in a held state: since step 2 the store keeps a `Paid` only
//!   on the minimal proof (`store::as_kept`). The padding case below
//!   measures what a padded `Paid` costs on arrival.
//! * **Despatches: one per order** (they are kept only while their order is,
//!   so the order cap is theirs): 256.
//! * **Backing slots: `MAX_BACKINGS` (64)** Ghost Keys, each backing carrying
//!   a certificate of `MAX_CERTIFICATE_PEM_BYTES` (4096). Half are retired,
//!   which is how a store reaches the bound in practice (rotation keeps the
//!   retired key's slot), and each of the other half holds
//!   `MAX_SCOPES_PER_BACKER` (4) wrapped copies of the store key: 64
//!   backings, 32 retirements, 128 copies.
//! * **The closed flag**: at most one closure, and it is there.
//! * **Photos: `MAX_IMAGES_HARD` (8) per listing**, each with a description
//!   of `MAX_ALT_CHARS` (200), the cover with a thumbnail.
//! * **Choices and delivery regions** at the bounds the UI applies before
//!   signing (the contract does not check them): `MAX_CHOICE_GROUPS` groups
//!   of `MAX_CHOICE_OPTIONS` options, `MAX_DELIVERY_REGIONS` regions, every
//!   name `MAX_TERM_NAME_CHARS` long.
//!
//! * **Listings: `MAX_LISTINGS` (128)**, each at `MAX_LISTING_BYTES` (32
//!   KiB) as it encodes (step 2): every field above at its largest, then
//!   the description padded until one more character would not fit, so the
//!   store keeps it. The two stores share 120 listings and each has 8 the
//!   other lacks; the merge keeps the 128 newest.
//! * **The pause**: one record, signed.
//!
//! What has NO cap in the contract, and the size chosen:
//!
//! * **Listing statuses** (one per listing here). Nothing bounds them: a
//!   status outlives the cut of its listing. Every state here stays under
//!   the node's own `MAX_STATE_SIZE` (50 MiB, freenet-core
//!   `wasm_runtime/state_store.rs`), which [`cases`] checks: a state over it
//!   is one no node stores, so measuring it would prove nothing.
//! * **A listing's title** (200 characters), and the store's own name and
//!   description ([`DESCRIPTION_BYTES`] = 16 KiB, the UI markdown renderer's
//!   `MAX_SOURCE_BYTES`, which shows no more than that).
//! * **The store's certificate PEM**, sized like a backing's (4096).
//!
//! Each state is built by `StoreStateV1::apply_delta` from the empty store,
//! so it is one the contract would hold, and passes `verify` natively before
//! it is handed over. Every signature verifies for real: a refused record
//! would measure a refusal, which is cheap, and the budget would pass for the
//! wrong reason. The store key, the backers and the bridge are fixed seeds,
//! the "random" bytes BLAKE3 output, and every time [`super::now`], so the
//! states are the same bytes on every run.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{anyhow, bail, Result};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use freenet_bitcoin_common::spv::testing::{build_tx, mine, sha256d_pub, EASIEST_BITS};
use freenet_bitcoin_common::spv::{merkle_root_from_branch, SpvProof};
use freenet_bitcoin_common::{
    BitcoinNetwork, BlockAnchor, BlockHash, BridgeId, Claim, ClaimBody, OutPoint, SignedClaim,
    SignedTipEntry, TipEntryBody, Txid,
};
use freenet_scaffold::ComposableState;
use harvest_common::backing::{
    sign_with_store_key, store_key_envelope, AuthorizedBacking, AuthorizedClosure,
    AuthorizedRetirement, BackingAcceptance, BackingStatement, Retirement, StoreClosure,
    MAX_BACKINGS, MAX_CERTIFICATE_PEM_BYTES,
};
use harvest_common::custody::{
    AuthorizedCopy, StoreKeyCopy, WrapScope, WrappedStoreKey, MAX_SCOPES_PER_BACKER, SCHEME_V1,
    WRAPPED_LEN_V1,
};
use harvest_common::fulfilment::{AuthorizedDespatch, Despatch};
use harvest_common::listing::{
    AuthorizedListing, AuthorizedListingStatus, ChoiceGroup, DeliveryPrice, FixedCheckout, Listing,
    ListingAvailability, ListingId, ListingKind, ListingStatus, PriceInfo, RegionPrice,
    MAX_CHOICE_GROUPS, MAX_CHOICE_OPTIONS, MAX_DELIVERY_REGIONS, MAX_TERM_NAME_CHARS,
};
use harvest_common::listing_image::{
    ImageBlob, ListingImage, MAX_ALT_CHARS, MAX_IMAGES_HARD, MAX_IMAGE_EDGE, MAX_THUMB_EDGE,
};
use harvest_common::payment::{AuthorizedOrder, Order, OrderId, OrderPaymentProof, OrderStatus};
use harvest_common::store::{
    AuthorizedStoreInfoV1, Bytes32, StoreInfoV1, StoreParameters, StoreStateV1, StoreStateV1Delta,
    MAX_ORDERS,
};

use super::{array, bytes, cbor, now, signing_key, Case, Kind, Update};

/// How many `Paid` records padded to [`PADDED_PROOF_BYTES`] the padding
/// case delivers in one delta: 16 MiB, well under the node's state limit.
const PADDED_ORDERS: u64 = 64;

/// About how large each padded proof is: `MAX_PROOF_CLAIM_BYTES`.
const PADDED_PROOF_BYTES: usize = 256 * 1024;

/// Listings in each at-cap store. The contract has no listing cap.
const LISTINGS: u64 = harvest_common::store::MAX_LISTINGS as u64;

/// How many of its listings the second store holds that the first does not.
/// The rest are the same listings, as two replicas of one shop share most of
/// theirs.
const LISTINGS_ONLY_IN_OTHER: u64 = 8;

/// A listing description, and the store's: the UI renderer's
/// `MAX_SOURCE_BYTES`, the most of one anybody is shown.
const DESCRIPTION_BYTES: usize = 16 * 1024;

const TITLE_CHARS: usize = 200;

/// freenet-core's `MAX_STATE_SIZE`: the largest state a node stores.
const NODE_MAX_STATE_BYTES: usize = 50 * 1024 * 1024;

/// Refuse a fixture state no node would store.
fn fits_a_node(what: &str, state: &StoreStateV1) -> Result<()> {
    let len = cbor(state).len();
    if len > NODE_MAX_STATE_BYTES {
        bail!("{what} is {len} bytes, over the node's {NODE_MAX_STATE_BYTES}-byte state limit");
    }
    Ok(())
}

/// Where every fixture payment confirms, and the tip the proofs carry.
const CONFIRM_HEIGHT: u32 = 100;

/// Merkle depth of a block of 2049 to 4096 transactions.
const MERKLE_DEPTH: usize = 12;

/// `len` characters of lowercase words: what a seller types, every byte of
/// it ASCII so characters and bytes agree. `spaces` off gives one unbroken
/// word, for names the UI trims.
fn text(label: &str, i: u64, len: usize, spaces: bool) -> String {
    bytes(label, i, len)
        .into_iter()
        .map(|b| match b % 32 {
            n if n < 26 => char::from(b'a' + n),
            _ if spaces => ' ',
            n => char::from(b'a' + n - 26),
        })
        .collect()
}

fn bytes32(label: &str, i: u64) -> Bytes32 {
    Bytes32(array(label, i))
}

/// The store's key, signer of everything it holds, and the bridge whose
/// observations settle its orders.
struct Shop {
    key: SigningKey,
    bridge: SigningKey,
    parameters: StoreParameters,
}

impl Shop {
    fn new() -> Self {
        let key = signing_key("store/key", 0);
        let parameters = StoreParameters::new(key.verifying_key());
        Self {
            key,
            bridge: signing_key("store/bridge", 0),
            parameters,
        }
    }

    fn owner(&self) -> VerifyingKey {
        self.key.verifying_key()
    }

    /// `(scoped_payload, signature)` over `value` by the store key, as the
    /// Harvest delegate signs it.
    fn sign<T: serde::Serialize>(&self, value: &T) -> Result<(Vec<u8>, Vec<u8>)> {
        sign_with_store_key(&self.key, cbor(value)).map_err(|e| anyhow!("store-key signing: {e}"))
    }

    /// The store's details at `version`, every text field at its size above.
    fn info(&self, label: &str, version: u32) -> Result<AuthorizedStoreInfoV1> {
        let info = StoreInfoV1 {
            version,
            certificate_pem: text(&format!("{label}/certificate"), 0, 4096, false),
            seller_fingerprint: bs58::encode(array::<32>(&format!("{label}/fingerprint"), 0))
                .into_string(),
            reputation_contract_id: array(&format!("{label}/reputation"), 0),
            store_name: text(&format!("{label}/name"), 0, TITLE_CHARS, true),
            description: text(&format!("{label}/description"), 0, DESCRIPTION_BYTES, true),
            encryption_public_key: Some(array(&format!("{label}/x25519"), 0)),
            // An RSA-2048 public key in PKCS#1 DER is 270 bytes. The
            // contract never parses it.
            record_public_key: Some(bytes(&format!("{label}/record-key"), 0, 270)),
        };
        let (scoped_payload, signature) = self.sign(&info)?;
        Ok(AuthorizedStoreInfoV1 {
            info,
            scoped_payload,
            signature,
        })
    }

    /// Listing `i`, every field at its largest. `label` decides its terms,
    /// so two stores that share a label share the listing.
    fn listing(&self, label: &str, i: u64) -> Result<AuthorizedListing> {
        self.listing_at(
            label,
            i,
            now() - chrono::Duration::days(30) + chrono::Duration::minutes(i as i64),
        )
    }

    /// Listing `i` at the store's per-listing bound
    /// ([`harvest_common::store::MAX_LISTING_BYTES`], step 2): every field
    /// at its largest, the description padded until one more character would
    /// not fit, so the store keeps it.
    fn listing_at(
        &self,
        label: &str,
        i: u64,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<AuthorizedListing> {
        let fits =
            |l: &AuthorizedListing| cbor(l).len() <= harvest_common::store::MAX_LISTING_BYTES;
        if !fits(&self.listing_sized(label, i, created_at, 0)?) {
            bail!("a listing with every field at its largest does not fit the listing bound");
        }
        let (mut lo, mut hi) = (0usize, DESCRIPTION_BYTES);
        while lo < hi {
            let mid = (lo + hi).div_ceil(2);
            if fits(&self.listing_sized(label, i, created_at, mid)?) {
                lo = mid;
            } else {
                hi = mid - 1;
            }
        }
        self.listing_sized(label, i, created_at, lo)
    }

    fn listing_sized(
        &self,
        label: &str,
        i: u64,
        created_at: chrono::DateTime<chrono::Utc>,
        description: usize,
    ) -> Result<AuthorizedListing> {
        let name = |what: &str, j: u64| {
            text(
                &format!("{label}/{what}"),
                i * 1000 + j,
                MAX_TERM_NAME_CHARS,
                false,
            )
        };
        let images = (0..MAX_IMAGES_HARD as u64)
            .map(|j| ListingImage {
                full: ImageBlob {
                    hash: bytes32(&format!("{label}/image"), i * 1000 + j),
                    len: 200 * 1024,
                    width: MAX_IMAGE_EDGE,
                    height: 1536,
                },
                thumb: (j == 0).then(|| ImageBlob {
                    hash: bytes32(&format!("{label}/thumb"), i),
                    len: 30 * 1024,
                    width: MAX_THUMB_EDGE,
                    height: 300,
                }),
                colour: array(&format!("{label}/colour"), i * 1000 + j),
                alt: text(&format!("{label}/alt"), i * 1000 + j, MAX_ALT_CHARS, true),
            })
            .collect();
        let choices = (0..MAX_CHOICE_GROUPS as u64)
            .map(|g| ChoiceGroup {
                name: name("choice", g),
                options: (0..MAX_CHOICE_OPTIONS as u64)
                    .map(|o| name("option", 100 + g * 20 + o))
                    .collect(),
            })
            .collect();
        let regions = (0..MAX_DELIVERY_REGIONS as u64)
            .map(|r| RegionPrice {
                region: name("region", 500 + r),
                sats: 2_000 + r * 100,
            })
            .collect();
        let listing = Listing {
            id: ListingId([0u8; 32]),
            title: text(&format!("{label}/title"), i, TITLE_CHARS, true),
            description: text(&format!("{label}/description"), i, description, true),
            kind: ListingKind::Sale,
            price: Some(PriceInfo {
                amount: "0.00125000".into(),
                currency: "BTC".into(),
            }),
            // The caller's: the delta's "newest" listing must rank newest, or
            // the store's cap could cut it and the delta would change nothing
            // (it ignored this argument before round 2 of step 2).
            created_at,
            checkout: Some(FixedCheckout {
                unit_sats: 125_000,
                delivery: DeliveryPrice::ByRegion(regions),
            }),
            choices,
            images,
        }
        .with_derived_id();
        if let Some(problem) = listing.checkout_problem().or(listing.choices_problem()) {
            bail!("the listing fixture breaks the UI's bounds: {problem}");
        }
        let (scoped_payload, signature) = self.sign(&listing)?;
        Ok(AuthorizedListing {
            listing,
            scoped_payload,
            signature,
            certificate_pem: text(&format!("{label}/listing-certificate"), 0, 4096, false),
        })
    }

    fn listing_status(
        &self,
        listing: &ListingId,
        revision: u64,
    ) -> Result<AuthorizedListingStatus> {
        let status = ListingStatus {
            listing: listing.clone(),
            revision,
            availability: ListingAvailability::Available {
                quantity: Some(1_000_000),
            },
        };
        let (scoped_payload, signature) = self.sign(&status)?;
        Ok(AuthorizedListingStatus {
            status,
            scoped_payload,
            signature,
        })
    }

    /// An instant-checkout order, `age` seconds old, paid by a transaction
    /// in a 12-deep Merkle tree and confirmed at [`CONFIRM_HEIGHT`].
    fn paid_order(&self, label: &str, i: u64, age: i64) -> Result<AuthorizedOrder> {
        self.paid_order_with(label, i, age, 0)
    }

    /// [`Self::paid_order`] whose payment's transaction also pays the
    /// largest number of filler outputs that keeps the record within
    /// `bytes` as it encodes (step 2's `store::MAX_PAID_ORDER_BYTES`): still
    /// the minimal proof, as large as a big honest transaction makes it.
    fn paid_order_at(
        &self,
        label: &str,
        i: u64,
        age: i64,
        bytes: usize,
    ) -> Result<AuthorizedOrder> {
        // At most 0xfc outputs in all: `build_tx` writes the count as one byte.
        let (mut lo, mut hi) = (0usize, 0xf9);
        while lo < hi {
            let mid = (lo + hi).div_ceil(2);
            if cbor(&self.paid_order_with(label, i, age, mid)?).len() <= bytes {
                lo = mid;
            } else {
                hi = mid - 1;
            }
        }
        let record = self.paid_order_with(label, i, age, lo)?;
        if cbor(&record).len() > bytes {
            bail!("a paid order does not fit {bytes} bytes even with no filler");
        }
        Ok(record)
    }

    fn paid_order_with(
        &self,
        label: &str,
        i: u64,
        age: i64,
        fillers: usize,
    ) -> Result<AuthorizedOrder> {
        // P2WPKH, as the delegate derives from a seller's BIP-84 wallet.
        let mut script = vec![0x00, 0x14];
        script.extend_from_slice(&bytes(&format!("{label}/script"), i, 20));
        let order = Order {
            id: OrderId([0u8; 32]),
            buyer_fingerprint: bs58::encode(array::<32>(&format!("{label}/buyer-fp"), i))
                .into_string(),
            seller_fingerprint: bs58::encode(array::<32>("store/seller-fp", 0)).into_string(),
            amount_sats: 125_000 * 3 + 2_000,
            network: BitcoinNetwork::Signet,
            payment_address: format!("tb1q{}", text(&format!("{label}/address"), i, 38, false)),
            payment_script_pubkey: script,
            required_confirmations: 1,
            payment_hash: None,
            trusted_bridges: vec![BridgeId(self.bridge.verifying_key().to_bytes())],
            bitcoin_address_code_hash: Some(array("store/address-code-hash", 0)),
            anchor: Some(BlockAnchor {
                height: CONFIRM_HEIGHT - 1,
                hash: BlockHash(array("store/order-anchor", 0)),
            }),
            order_binding: Some(array(&format!("{label}/binding"), i)),
            listing_tag: Some(array(&format!("{label}/listing-tag"), i)),
            buyer_receipt_key: Some(
                signing_key(&format!("{label}/buyer"), i)
                    .verifying_key()
                    .to_bytes(),
            ),
            request_id: Some(array(&format!("{label}/request"), i)),
            created_at: now() - chrono::Duration::seconds(age),
        }
        .with_derived_id();

        // The payment and the buyer's change.
        let mut change = vec![0x00, 0x14];
        change.extend_from_slice(&bytes(&format!("{label}/change"), i, 20));
        let mut outputs = vec![
            (order.amount_sats, order.payment_script_pubkey.clone()),
            (1_734_221, change),
        ];
        outputs.extend((0..fillers).map(|_| (546, vec![0x6a; 250])));
        let raw_tx = build_tx(&outputs);
        let txid = Txid(sha256d_pub(&raw_tx));
        let merkle_branch: Vec<[u8; 32]> = (0..MERKLE_DEPTH as u64)
            .map(|d| array(&format!("{label}/merkle"), i * 100 + d))
            .collect();
        let tx_index = 1 + (i as u32 % 4000);
        let root = merkle_root_from_branch(&txid, &merkle_branch, tx_index)
            .map_err(|e| anyhow!("merkle root: {e:?}"))?;
        let header = mine(
            array(&format!("{label}/prev-block"), i),
            root,
            1_790_000_000,
            EASIEST_BITS,
        );
        let block = BlockHash(sha256d_pub(&header.0));
        let anchor = BlockAnchor {
            height: CONFIRM_HEIGHT,
            hash: block,
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
                    spv: SpvProof {
                        raw_tx,
                        merkle_branch,
                        tx_index,
                        header,
                        following_headers: vec![],
                    },
                },
            },
        )
        .map_err(|e| anyhow!("sign claim: {e:?}"))?;
        let tip = SignedTipEntry::sign(
            &self.bridge,
            &TipEntryBody {
                network: order.network,
                anchor: BlockAnchor {
                    height: CONFIRM_HEIGHT,
                    hash: BlockHash(array("store/tip", 0)),
                },
                prev_hash: BlockHash(array("store/tip-prev", 0)),
                block_time: 1_790_000_000,
                tx_count: 3_000,
                median_time: 1_789_999_000,
            },
        )
        .map_err(|e| anyhow!("sign tip: {e:?}"))?;
        let (scoped_payload, signature) = self.sign(&order)?;
        Ok(AuthorizedOrder {
            order,
            scoped_payload,
            signature,
            status: OrderStatus::Paid,
            payment_proof: Some(OrderPaymentProof::on_chain(vec![claim], tip)),
            status_scoped_payload: None,
            status_signature: None,
        })
    }

    /// [`Self::paid_order`] with its proof padded to about
    /// [`PADDED_PROOF_BYTES`] by claims of one satoshi each about other
    /// outpoints, every one confirmed inside the window (the genuine claim,
    /// last, already covers the amount). The store's rule (`store::as_kept`,
    /// step 2) checks the record's size first, so a record this large is kept
    /// as its unpaid terms without its proof being folded: what this costs is
    /// decoding the delta and re-encoding each record to size it. A record
    /// under `MAX_PAID_ORDER_BYTES` is the one whose proof is folded.
    fn padded_paid_order(&self, label: &str, i: u64) -> Result<AuthorizedOrder> {
        let mut record = self.paid_order(label, i, 0)?;
        let Some(OrderPaymentProof::OnChain(proof)) = record.payment_proof.take() else {
            bail!("the fixture's proof is on-chain");
        };
        let genuine = proof.claims[0].clone();
        let anchor = BlockAnchor {
            height: CONFIRM_HEIGHT,
            hash: BlockHash(array("store/padding-block", 0)),
        };
        let mut claims = Vec::new();
        let mut size = cbor(&genuine).len();
        let mut j = 0u64;
        while size < PADDED_PROOF_BYTES {
            let raw_tx = bytes(&format!("{label}/padding-tx"), i * 1000 + j, 8 * 1024);
            let claim = SignedClaim::sign(
                &self.bridge,
                &ClaimBody {
                    script_id: record.order.bitcoin_params().script_id(),
                    network: record.order.network,
                    as_of: anchor,
                    claim: Claim::ConfirmedOutput {
                        outpoint: OutPoint {
                            txid: Txid(array(&format!("{label}/padding-txid"), i * 1000 + j)),
                            vout: 0,
                        },
                        value_sats: 1,
                        anchor,
                        spv: SpvProof {
                            raw_tx,
                            merkle_branch: Vec::new(),
                            tx_index: 0,
                            header: mine([0u8; 32], [0u8; 32], 1_790_000_000, EASIEST_BITS),
                            following_headers: vec![],
                        },
                    },
                },
            )
            .map_err(|e| anyhow!("sign padding claim: {e:?}"))?;
            size += cbor(&claim).len();
            claims.push(claim);
            j += 1;
        }
        claims.push(genuine);
        record.payment_proof = Some(OrderPaymentProof::on_chain(claims, proof.tip));
        Ok(record)
    }

    fn despatch(&self, order: &OrderId, i: u64) -> Result<AuthorizedDespatch> {
        let despatch = Despatch {
            order_id: order.clone(),
            anchor: BlockAnchor {
                height: CONFIRM_HEIGHT + 6,
                hash: BlockHash(array("store/despatch-anchor", i % 16)),
            },
        };
        let (scoped_payload, signature) = self.sign(&despatch)?;
        Ok(AuthorizedDespatch {
            despatch,
            scoped_payload,
            signature,
        })
    }

    /// Backer `j`'s backing: signed by the backer through the vault, accepted
    /// by the store key.
    fn backing(&self, backer: &SigningKey, label: &str, j: u64) -> Result<AuthorizedBacking> {
        let statement = BackingStatement {
            store: self.owner(),
            backer: backer.verifying_key(),
            certificate_pem: text(
                &format!("{label}/certificate"),
                j,
                MAX_CERTIFICATE_PEM_BYTES,
                false,
            ),
            network: BitcoinNetwork::Signet,
            block: BlockAnchor {
                height: 50 + j as u32,
                hash: BlockHash(array(&format!("{label}/block"), j)),
            },
        };
        let backer_scoped_payload =
            store_key_envelope(cbor(&statement)).map_err(|e| anyhow!("envelope: {e}"))?;
        let backer_signature = backer.sign(&backer_scoped_payload).to_bytes().to_vec();
        let (acceptance_scoped_payload, acceptance_signature) = self.sign(&BackingAcceptance {
            backing: statement.clone(),
        })?;
        Ok(AuthorizedBacking {
            statement,
            backer_scoped_payload,
            backer_signature,
            acceptance_scoped_payload,
            acceptance_signature,
        })
    }

    fn retirement(&self, backer: &SigningKey) -> Result<AuthorizedRetirement> {
        let retirement = Retirement {
            backer: backer.verifying_key(),
        };
        let (scoped_payload, signature) = self.sign(&retirement)?;
        Ok(AuthorizedRetirement {
            retirement,
            scoped_payload,
            signature,
        })
    }

    fn copy(&self, backer: &SigningKey, label: &str, j: u64, scope: u64) -> Result<AuthorizedCopy> {
        let copy = StoreKeyCopy {
            store: self.owner(),
            backer: backer.verifying_key(),
            scope: WrapScope(array(&format!("{label}/scope"), scope)),
            wrapped: WrappedStoreKey {
                scheme: SCHEME_V1,
                ciphertext: bytes(&format!("{label}/wrapped"), j * 10 + scope, WRAPPED_LEN_V1),
            },
        };
        let (scoped_payload, signature) = self.sign(&copy)?;
        Ok(AuthorizedCopy {
            copy,
            scoped_payload,
            signature,
        })
    }

    /// The seller's pause (step 2), at `revision`.
    fn pause(&self, revision: u64) -> Result<harvest_common::store_pause::AuthorizedStorePause> {
        let pause = harvest_common::store_pause::StorePause::new(self.owner(), revision, true);
        let (scoped_payload, signature) = self.sign(&pause)?;
        Ok(harvest_common::store_pause::AuthorizedStorePause {
            pause,
            scoped_payload,
            signature,
        })
    }

    fn closure(&self) -> Result<AuthorizedClosure> {
        let closure = StoreClosure {
            store: self.owner(),
        };
        let (scoped_payload, signature) = self.sign(&closure)?;
        Ok(AuthorizedClosure {
            closure,
            scoped_payload,
            signature,
        })
    }

    /// A store at every cap.
    ///
    /// * `label` keeps two stores' orders and backers apart.
    /// * `listings` are the listing indices it holds, all from one shared
    ///   label so two stores holding an index hold the same listing.
    /// * `revision` is its listing statuses' revision: the higher one wins
    ///   a merge.
    /// * Its orders are dated `offset + 60`, `offset + 62`, ... seconds ago,
    ///   so two stores built with offsets 0 and 1 interleave and the order
    ///   cap keeps half of each.
    fn at_cap(
        &self,
        label: &str,
        version: u32,
        listings: std::ops::Range<u64>,
        revision: u64,
        offset: i64,
    ) -> Result<StoreStateV1> {
        self.at_cap_paid(label, version, listings, revision, offset, None)
    }

    /// [`Self::at_cap`], each paid order at `paid_bytes` as it encodes when
    /// given.
    fn at_cap_paid(
        &self,
        label: &str,
        version: u32,
        listings: std::ops::Range<u64>,
        revision: u64,
        offset: i64,
        paid_bytes: Option<usize>,
    ) -> Result<StoreStateV1> {
        let listings = listings
            .map(|i| self.listing("store/listing", i))
            .collect::<Result<Vec<_>>>()?;
        let listing_statuses = listings
            .iter()
            .map(|l| self.listing_status(&l.listing.id, revision))
            .collect::<Result<Vec<_>>>()?;
        let orders = (0..MAX_ORDERS as u64)
            .map(|i| match paid_bytes {
                Some(bytes) => self.paid_order_at(label, i, offset + 60 + 2 * i as i64, bytes),
                None => self.paid_order(label, i, offset + 60 + 2 * i as i64),
            })
            .collect::<Result<Vec<_>>>()?;
        let fulfilment = orders
            .iter()
            .enumerate()
            .map(|(i, o)| self.despatch(&o.order.id, i as u64))
            .collect::<Result<Vec<_>>>()?;

        let backers: Vec<SigningKey> = (0..MAX_BACKINGS as u64)
            .map(|j| signing_key(&format!("{label}/backer"), j))
            .collect();
        let backings = backers
            .iter()
            .enumerate()
            .map(|(j, b)| self.backing(b, label, j as u64))
            .collect::<Result<Vec<_>>>()?;
        let (retired, current) = backers.split_at(MAX_BACKINGS / 2);
        let retirements = retired
            .iter()
            .map(|b| self.retirement(b))
            .collect::<Result<Vec<_>>>()?;
        let mut copies = Vec::new();
        for (j, b) in current.iter().enumerate() {
            for scope in 0..MAX_SCOPES_PER_BACKER as u64 {
                copies.push(self.copy(b, label, j as u64, scope)?);
            }
        }

        let delta = StoreStateV1Delta {
            owner: Some(self.owner()),
            info: Some(self.info(label, version)?),
            listings: Some(listings),
            orders: Some(orders),
            backings: Some(backings),
            retirements: Some(retirements),
            closed: Some(vec![self.closure()?]),
            copies: Some(copies),
            fulfilment: Some(fulfilment),
            listing_statuses: Some(listing_statuses),
            pause: Some(vec![self.pause(u64::from(version))?]),
        };
        let mut state = StoreStateV1::default();
        state
            .apply_delta(&StoreStateV1::default(), &self.parameters, &Some(delta))
            .map_err(|e| anyhow!("building the store fixture: {e}"))?;
        self.check(&state, "the store fixture")?;
        Ok(state)
    }

    /// `state` verifies, and every capped part is full.
    fn check(&self, state: &StoreStateV1, what: &str) -> Result<()> {
        state
            .verify(state, &self.parameters)
            .map_err(|e| anyhow!("{what} fails verify: {e}"))?;
        let slots: BTreeSet<Bytes32> = state
            .backings
            .records
            .keys()
            .chain(state.retirements.records.keys())
            .copied()
            .chain(
                state
                    .copies
                    .records
                    .values()
                    .map(|c| Bytes32(c.copy.backer.to_bytes())),
            )
            .collect();
        let mut per_backer: BTreeMap<Bytes32, usize> = BTreeMap::new();
        for c in state.copies.records.values() {
            *per_backer
                .entry(Bytes32(c.copy.backer.to_bytes()))
                .or_default() += 1;
        }
        let unretired = state
            .backings
            .records
            .keys()
            .filter(|k| !state.retirements.records.contains_key(*k))
            .count();
        let full = state.orders.orders.len() == MAX_ORDERS
            && state.fulfilment.records.len() == MAX_ORDERS
            && slots.len() == MAX_BACKINGS
            && per_backer.len() == unretired
            && per_backer.values().all(|&n| n == MAX_SCOPES_PER_BACKER)
            && state.closed.records.len() == 1
            && state
                .listings
                .listings
                .iter()
                .all(|l| l.listing.images.len() == MAX_IMAGES_HARD)
            && state.listings.listings.len() == harvest_common::store::MAX_LISTINGS
            // A status outlives the cut of its listing (step 2).
            && state.listing_statuses.records.len() >= state.listings.listings.len()
            && state.pause.records.len() == 1
            // Every order still `Paid`: one the store kept as its unpaid
            // terms (`store::as_kept`) would make this a cheaper state than
            // the rows say it is.
            && state
                .orders
                .orders
                .values()
                .all(|o| o.status == harvest_common::payment::OrderStatus::Paid);
        if !full {
            bail!(
                "{what} is not at its caps, every order paid: {} orders ({} paid), {} despatches, \
                 {} backing slots, {} backers with copies of {unretired} unretired, {} listings, \
                 {} statuses",
                state.orders.orders.len(),
                state
                    .orders
                    .orders
                    .values()
                    .filter(|o| o.status == harvest_common::payment::OrderStatus::Paid)
                    .count(),
                state.fulfilment.records.len(),
                slots.len(),
                per_backer.len(),
                state.listings.listings.len(),
                state.listing_statuses.records.len(),
            );
        }
        Ok(())
    }
}

pub fn cases() -> Result<Vec<Case>> {
    let shop = Shop::new();
    let parameters = cbor(&shop.parameters);
    let held = shop.at_cap("store/held", 2, 0..LISTINGS, 1, 0)?;
    let held_bytes = cbor(&held);

    // (a) A seller publishing one more listing, as the UI sends it
    // (`gateway/store_ops::listings_delta_bytes`): the owner and the one
    // listing, every other part absent.
    let one = StoreStateV1Delta {
        owner: Some(shop.owner()),
        // The newest, so the store's cut keeps it and drops its oldest.
        listings: Some(vec![shop.listing_at("store/new-listing", 0, now())?]),
        ..Default::default()
    };

    // The delta must change the store, or its row measures a no-op: the
    // listing it adds is the newest, so the cut keeps it and drops the
    // oldest (it was dated as the oldest before round 2 of step 2, and at
    // 128 listings the store cut it on arrival).
    {
        let mut after = held.clone();
        after
            .apply_delta(&held, &shop.parameters, &Some(one.clone()))
            .map_err(|e| anyhow!("the one-listing delta applies natively: {e}"))?;
        if after.listings == held.listings {
            bail!("the one-listing delta changes nothing: its listing is cut on arrival");
        }
    }

    // (b) A full state of the same store from a replica that has diverged:
    // later details, eight listings this one lacks and a later status for
    // every shared one, `MAX_ORDERS` different orders interleaved in time
    // with the held ones (the cap keeps the newest half of each), and 64 different
    // backers (the cap keeps the 64 smallest of the 128). Every part
    // therefore brings something, and the merge is still at every cap.
    let other = shop.at_cap(
        "store/other",
        3,
        LISTINGS_ONLY_IN_OTHER..LISTINGS + LISTINGS_ONLY_IN_OTHER,
        2,
        1,
    )?;
    let mut merged = held.clone();
    merged
        .merge(&held, &shop.parameters, &other)
        .map_err(|e| anyhow!("merging the two store fixtures natively: {e}"))?;
    shop.check(&merged, "the merge of the two store fixtures")?;
    if merged == held {
        bail!("the second store fixture brings nothing to the first");
    }
    // (c) Step 2: `Paid` records padded to the proof bound, as anyone may
    // publish one, the newest orders there are. The store keeps each as its
    // unpaid terms (`store::as_kept`), refused by its size.
    let padded = StoreStateV1Delta {
        owner: Some(shop.owner()),
        orders: Some(
            (0..PADDED_ORDERS)
                .map(|i| shop.padded_paid_order("store/padded", i))
                .collect::<Result<Vec<_>>>()?,
        ),
        ..Default::default()
    };
    {
        let mut kept = held.clone();
        kept.apply_delta(&held, &shop.parameters, &Some(padded.clone()))
            .map_err(|e| anyhow!("the padded delta applies natively: {e}"))?;
        let unpaid = kept
            .orders
            .orders
            .values()
            .filter(|o| o.status == OrderStatus::AwaitingPayment)
            .count();
        if unpaid != PADDED_ORDERS as usize {
            bail!("the padded orders are not all kept unpaid ({unpaid})");
        }
        kept.verify(&kept, &shop.parameters)
            .map_err(|e| anyhow!("the store after the padded delta fails verify: {e}"))?;
    }
    // (d) Step 2: every paid order at the store's byte bound for a `Paid`
    // record (`store::MAX_PAID_ORDER_BYTES`), as big honest payments make
    // them, beside the listings at theirs.
    let big = shop.at_cap_paid(
        "store/held-big",
        2,
        0..LISTINGS,
        1,
        0,
        Some(harvest_common::store::MAX_PAID_ORDER_BYTES),
    )?;
    for (what, bytes) in [
        ("held store", held_bytes.len()),
        ("other store", cbor(&other).len()),
        ("merged store", cbor(&merged).len()),
        ("store of paid orders at their byte bound", cbor(&big).len()),
        ("one-listing delta", cbor(&one).len()),
        ("padded delta", cbor(&padded).len()),
        (
            "a status",
            cbor(&held.listing_statuses.records.values().next()).len(),
        ),
    ] {
        println!("store      size: {what}: {bytes} bytes");
    }
    fits_a_node("the store of paid orders at their byte bound", &big)?;
    fits_a_node("the held store fixture", &held)?;
    fits_a_node("the second store fixture", &other)?;
    fits_a_node("the merge of the two store fixtures", &merged)?;

    // (e) Measuring the hostile delta against the honest one it must not
    // outcost: padded `Paid` deltas of several sizes, and the largest honest
    // delta there is, a new subscriber's whole store of paid orders at their
    // byte bound.
    let padded_of = |n: u64| -> Result<Vec<u8>> {
        Ok(cbor(&StoreStateV1Delta {
            owner: Some(shop.owner()),
            orders: Some(
                (0..n)
                    .map(|i| shop.padded_paid_order("store/padded", i))
                    .collect::<Result<Vec<_>>>()?,
            ),
            ..Default::default()
        }))
    };
    let whole = {
        use freenet_scaffold::ComposableState;
        let empty = StoreStateV1::default();
        let summary = empty.summarize(&empty, &shop.parameters);
        cbor(
            &big.delta(&big, &shop.parameters, &summary)
                .ok_or_else(|| anyhow!("a whole store has a delta to an empty one"))?,
        )
    };
    println!("store      size: whole-store delta: {} bytes", whole.len());
    // The most padded records a delta under `MAX_STORE_BYTES` carries: the
    // worst a hostile delta can do now. One more record is past the bound.
    let bound = harvest_common::store::MAX_STORE_BYTES;
    let mut n = 1u64;
    while padded_of(n + 1)?.len() <= bound {
        n += 1;
    }
    let at_bound = padded_of(n)?;
    let past_bound = padded_of(n + 1)?;
    println!(
        "store      size: {n}-record padded delta: {} bytes (bound {bound})",
        at_bound.len()
    );
    if whole.len() > bound || cbor(&big).len() > bound {
        bail!("the largest honest store, or its whole-store delta, is past MAX_STORE_BYTES");
    }
    let mut sized = vec![
        Case {
            kind: Kind::Store,
            name: format!("{MAX_ORDERS} orders at caps + {n} padded Paid, the most under the store's byte bound"),
            parameters: parameters.clone(),
            held: held_bytes.clone(),
            update: Update::Delta(at_bound),
        },
        Case {
            kind: Kind::Store,
            name: format!("{MAX_ORDERS} orders at caps + {} padded Paid, past the store's byte bound (refused)", n + 1),
            parameters: parameters.clone(),
            held: held_bytes.clone(),
            update: Update::RefusedDelta(past_bound),
        },
    ];
    // (f) Replayed genuine records (review round 4 of step 2): copies of
    // records the store holds, beside the one new listing, are not
    // verified again. 256 copies of a held paid order (the most an order
    // delta may carry) and 4,000 of a held listing status.
    let held_order = held
        .orders
        .orders
        .values()
        .next()
        .cloned()
        .ok_or_else(|| anyhow!("the held store has orders"))?;
    let held_status = held
        .listing_statuses
        .records
        .values()
        .next()
        .cloned()
        .ok_or_else(|| anyhow!("the held store has statuses"))?;
    for (what, delta) in [
        (
            format!("{MAX_ORDERS} copies of a held paid order"),
            StoreStateV1Delta {
                orders: Some(vec![held_order.clone(); MAX_ORDERS]),
                ..one.clone()
            },
        ),
        (
            "4000 copies of a held listing status".to_string(),
            StoreStateV1Delta {
                listing_statuses: Some(vec![held_status.clone(); 4000]),
                ..one.clone()
            },
        ),
    ] {
        sized.push(Case {
            kind: Kind::Store,
            name: format!("{MAX_ORDERS} orders at caps + one-listing delta + {what}"),
            parameters: parameters.clone(),
            held: held_bytes.clone(),
            update: Update::Delta(cbor(&delta)),
        });
    }
    sized.push(Case {
        kind: Kind::Store,
        name: "a new subscriber's whole store (paid orders at their byte bound) as one delta"
            .into(),
        parameters: parameters.clone(),
        held: Vec::new(),
        update: Update::Delta(whole),
    });

    let mut cases = vec![
        Case {
            kind: Kind::Store,
            name: format!("{MAX_ORDERS} orders at caps + one-listing delta"),
            parameters: parameters.clone(),
            held: held_bytes.clone(),
            update: Update::Delta(cbor(&one)),
        },
        Case {
            kind: Kind::Store,
            name: format!("{MAX_ORDERS} orders at caps + another at-caps state"),
            parameters: parameters.clone(),
            held: held_bytes.clone(),
            update: Update::State(cbor(&other)),
        },
        Case {
            kind: Kind::Store,
            name: format!(
                "{MAX_ORDERS} Paid orders of {} KiB + one-listing delta",
                harvest_common::store::MAX_PAID_ORDER_BYTES / 1024
            ),
            parameters: parameters.clone(),
            held: cbor(&big),
            update: Update::Delta(cbor(&one)),
        },
    ];
    cases.extend(sized);
    Ok(cases)
}
