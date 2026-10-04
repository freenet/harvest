//! The store at its caps (harvest#226).
//!
//! What `harvest_common::store` bounds, and what this fixture puts there:
//!
//! * **Orders: [`MAX_ORDERS`] (4096)**, every one `Paid` with a genuine SPV
//!   payment proof, the status whose `verify` costs the most (the seller's
//!   signature on the terms, then the bridge's signed tip, the bridge's
//!   signed claim and the SPV proof inside it). Each is an instant-checkout
//!   answer, so every optional field is filled (request id, binding, listing
//!   tag, buyer receipt key, anchor, address-contract hash). The proof is the
//!   one the UI publishes (`minimal_on_chain_proof`, one claim) for a
//!   two-output transaction in a block of a few thousand, so its Merkle
//!   branch is 12 hashes deep. `MAX_PROOF_CLAIM_BYTES` (256 KiB a proof) is
//!   NOT filled: the merge keeps the smaller of two proofs for one order, so
//!   padding a proof is not a state a replica keeps, and 4096 orders at 256
//!   KiB would be a 1 GiB state no node holds.
//! * **Despatches: one per order** (they are kept only while their order is,
//!   so the order cap is theirs): 4096.
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
//! What has NO cap in the contract, and the size chosen:
//!
//! * **Listings** ([`LISTINGS`] = 64) and **listing statuses** (one per
//!   listing). Nothing in the contract bounds either. What bounds them here
//!   is the node's own `MAX_STATE_SIZE` (50 MiB, freenet-core
//!   `wasm_runtime/state_store.rs`): the capped parts alone encode to about
//!   41 MB (the 4096 paid orders are about 34 MB of it, since every
//!   `Vec<u8>` and byte array in an order is a CBOR integer array), and a
//!   listing at the sizes below is about 115 KB, so 64 of them, and the 72
//!   the merge produces, keep every state here under the node's limit. A
//!   state over it is one no node stores, so measuring it would prove
//!   nothing. [`cases`] checks every state against that limit.
//! * **A listing's title** (200 characters) and **description**
//!   ([`DESCRIPTION_BYTES`] = 16 KiB), and the store's own name and
//!   description. 16 KiB is the UI markdown renderer's `MAX_SOURCE_BYTES`:
//!   it shows no more than that, so a longer description is bytes nobody
//!   reads.
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

/// Listings in each at-cap store. The contract has no listing cap.
const LISTINGS: u64 = 64;

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
            description: text(&format!("{label}/description"), i, DESCRIPTION_BYTES, true),
            kind: ListingKind::Sale,
            price: Some(PriceInfo {
                amount: "0.00125000".into(),
                currency: "BTC".into(),
            }),
            created_at: now() - chrono::Duration::days(30) + chrono::Duration::minutes(i as i64),
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
        let raw_tx = build_tx(&[
            (order.amount_sats, order.payment_script_pubkey.clone()),
            (1_734_221, change),
        ]);
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
        let listings = listings
            .map(|i| self.listing("store/listing", i))
            .collect::<Result<Vec<_>>>()?;
        let listing_statuses = listings
            .iter()
            .map(|l| self.listing_status(&l.listing.id, revision))
            .collect::<Result<Vec<_>>>()?;
        let orders = (0..MAX_ORDERS as u64)
            .map(|i| self.paid_order(label, i, offset + 60 + 2 * i as i64))
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
            && state.listing_statuses.records.len() == state.listings.listings.len();
        if !full {
            bail!(
                "{what} is not at its caps: {} orders, {} despatches, {} backing slots, \
                 {} backers with copies of {unretired} unretired, {} listings, {} statuses",
                state.orders.orders.len(),
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
        listings: Some(vec![shop.listing("store/new-listing", 0)?]),
        ..Default::default()
    };

    // (b) A full state of the same store from a replica that has diverged:
    // later details, eight listings this one lacks and a later status for
    // every shared one, 4096 different orders interleaved in time with the
    // held ones (the cap keeps the newest 2048 of each), and 64 different
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
    fits_a_node("the held store fixture", &held)?;
    fits_a_node("the second store fixture", &other)?;
    fits_a_node("the merge of the two store fixtures", &merged)?;

    Ok(vec![
        Case {
            kind: Kind::Store,
            name: "4096 orders at caps + one-listing delta".into(),
            parameters: parameters.clone(),
            held: held_bytes.clone(),
            update: Update::Delta(cbor(&one)),
        },
        Case {
            kind: Kind::Store,
            name: "4096 orders at caps + another at-caps state".into(),
            parameters,
            held: held_bytes,
            update: Update::State(cbor(&other)),
        },
    ])
}
