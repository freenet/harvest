//! The seller's long-term X25519 secret, and the only thing it is used for.
//!
//! # What this holds and why it cannot live anywhere else
//!
//! A buyer has no identity in Harvest -- no ghostkey, no account, nothing to
//! register. Their Bitcoin payment is their whole commitment. So the key
//! exchange is one-sided: the buyer generates an ephemeral keypair per order
//! and encrypts to a key the SELLER published, and the seller's half of that
//! exchange has to outlive any one page load or no buyer could ever reach
//! them.
//!
//! That makes it a durable secret, which in Harvest means the delegate's own
//! secret store -- the same place the reputation signing key and the Bitcoin
//! account key live. It is reached only through [`crate::origin::authorize`],
//! along with every other request family; see that module for what the gate
//! is worth and what it is not.
//!
//! # What leaves, and what does not
//!
//! The secret itself never leaves. [`derive_conversation_keys`] answers
//! per-buyer conversation keys, which decrypt one buyer's messages and
//! nothing else; the secret decrypts every conversation the seller will ever
//! have, including ones that have not happened yet.
//!
//! The alternative -- decrypting here and answering plaintext -- would need
//! the padding, CBOR and AES-GCM path inside the delegate. That path lives in
//! `harvest-ui`'s `messaging`, and the only crate both sides share is
//! `harvest-common`, which is compiled into all three contracts. Moving it
//! there would put `aes-gcm` in every contract's WASM to serve code no
//! contract executes. One crypto path, in the UI, is the trade that was made.
//!
//! # The buyer's half, which is not symmetrical with the seller's
//!
//! The second half of this module keeps the BUYER's per-conversation
//! ephemeral secrets, and it exists for a different reason. The seller's
//! secret is here because it must outlive a page load or no buyer could ever
//! reach them. The buyer's is here because there is nowhere else at all: the
//! Freenet webapp iframe carries no `allow-same-origin`, so the page runs on
//! an opaque origin where `localStorage`, `sessionStorage`, IndexedDB and
//! cookies all throw. Without this the buyer's keys die with the tab, and the
//! seller's reply -- which after Phase 2 carries the buyer's only capability
//! to complain against the seller's bond -- becomes unreadable by anyone,
//! including the buyer who asked for it.
//!
//! Nothing here is keyed by a ghostkey fingerprint, because the buyer has no
//! identity to key by. See `docs/buyer-conversation-persistence.md` for the
//! whole design, including the two things it does not solve: a buyer who
//! changes device, and the durable local record this leaves of who they
//! contacted.

use crate::secrets::RemovableSecrets;
use freenet_migrate::SecretStore;
use harvest_common::delegate::{
    BackupString, ConversationKey, ConversationSecret, EvictedConversation,
    HarvestDelegateResponse, ImportedConversation, RecalledConversation, RequestId,
};
use harvest_common::mailbox::{conversation_key_from_dh, MessageDirection};
use x25519_dalek::{PublicKey, StaticSecret};

/// Where this identity's X25519 secret lives.
///
/// Under `harvest:` like everything else the delegate writes, because the
/// migration export is defined by that prefix -- a key builder that stopped
/// starting with it would be silently left behind by every future migration.
/// Pinned by `handlers::all_secret_key_shapes` and the export test that reads
/// it.
pub(crate) fn x25519_sk_key(fp: &str) -> Vec<u8> {
    format!("harvest:x25519_sk:{fp}").into_bytes()
}

/// Mint this identity's X25519 keypair, or recall the one already minted.
///
/// Idempotent on purpose. The public half goes into a signed `StoreInfoV1`
/// that lives on the network permanently, and buyers encrypt to whatever they
/// read there. Minting a second key would leave every message already sent to
/// the first one undecryptable, with no error anywhere -- so a key that
/// exists is returned unchanged, and the UI may call this on every connect.
pub(crate) fn init_encryption_key<S: SecretStore>(
    store: &mut S,
    ghostkey_fingerprint: &str,
    recall_only: bool,
) -> HarvestDelegateResponse {
    let key = x25519_sk_key(ghostkey_fingerprint);

    let secret = match store.get_secret(&key).and_then(seed_from_stored) {
        Some(existing) => existing,
        // A recall that finds nothing mints nothing: the UI asks this way
        // before the delegate secret migration has run (harvest#123).
        None if recall_only => {
            return HarvestDelegateResponse::EncryptionKeyAbsent {
                ghostkey_fingerprint: ghostkey_fingerprint.to_string(),
            }
        }
        None => {
            let mut seed = [0u8; 32];
            // The delegate host's own RNG, via this crate's registered
            // `getrandom` implementation (see `lib.rs`). Not
            // `StaticSecret::random`, which would reach `rand_core::OsRng`
            // and give the crate a second entropy path to reason about.
            if let Err(e) = getrandom::getrandom(&mut seed) {
                return HarvestDelegateResponse::Error {
                    message: format!("could not generate an encryption key: {e}"),
                };
            }
            // The write, and only then the answer. A public key handed back
            // whose private half was never stored is published by the seller
            // into a permanent record, and every buyer who reads it encrypts
            // to a key nobody holds -- their messages arrive, look sent, and
            // can never be read. Reporting the failure leaves the seller with
            // no published key, which the UI can say out loud and which is
            // recoverable.
            if !store.set_secret(&key, &seed) {
                return HarvestDelegateResponse::Error {
                    message: "could not store the encryption key -- the node refused the write, \
                              so no key was published"
                        .into(),
                };
            }
            StaticSecret::from(seed)
        }
    };

    HarvestDelegateResponse::EncryptionKeyReady {
        ghostkey_fingerprint: ghostkey_fingerprint.to_string(),
        x25519_public_key: PublicKey::from(&secret).as_bytes().to_vec(),
    }
}

/// Read a stored 32-byte seed back as a secret, or `None` if the stored value
/// is not one.
///
/// A wrong-length value is treated as absent rather than as a reason to fail:
/// the only way to get one is for something outside this module to write the
/// key, and re-minting is the recoverable answer. It is not silent -- the
/// caller mints a new key, whose public half differs from whatever was
/// published, which the seller sees as messaging having stopped working.
fn seed_from_stored(stored: Vec<u8>) -> Option<StaticSecret> {
    let seed: [u8; 32] = stored.try_into().ok()?;
    Some(StaticSecret::from(seed))
}

/// Derive one conversation key per buyer ephemeral public key.
///
/// Malformed and low-order peer keys are dropped rather than answered, so the
/// result may be shorter than the request. That is why every entry echoes the
/// [`ConversationKey::peer_public_key`] it belongs to: correlating by
/// position would, the first time an entry was dropped, hand one buyer's
/// conversation key to another buyer's messages.
pub(crate) fn derive_conversation_keys<S: SecretStore>(
    store: &S,
    request_id: RequestId,
    ghostkey_fingerprint: &str,
    peer_public_keys: &[Vec<u8>],
    store_verifying_key: Option<[u8; 32]>,
) -> HarvestDelegateResponse {
    // A store with its own key reads with the inbox key that key derives
    // (harvest#93 phase 1b): the same on every device holding the store
    // key, so a second device, or one that recovered the key after a
    // delegate re-key, reads the same messages.
    if let Some(store_key) = store_verifying_key {
        let secret = ed25519_dalek::VerifyingKey::from_bytes(&store_key)
            .ok()
            .and_then(|vk| crate::store_keys::load(store, &vk))
            .map(|sk| harvest_common::custody::inbox_secret(&sk));
        return match secret {
            Some(secret) => {
                conversation_keys_from(request_id, ghostkey_fingerprint, &secret, peer_public_keys)
            }
            None => HarvestDelegateResponse::ConversationKeys {
                request_id,
                ghostkey_fingerprint: ghostkey_fingerprint.to_string(),
                result: Err("this device does not hold that store's key".into()),
            },
        };
    }
    let Some(secret) = store
        .get_secret(&x25519_sk_key(ghostkey_fingerprint))
        .and_then(seed_from_stored)
    else {
        return HarvestDelegateResponse::ConversationKeys {
            request_id,
            ghostkey_fingerprint: ghostkey_fingerprint.to_string(),
            result: Err(format!(
                "no encryption key for ghostkey {ghostkey_fingerprint} -- call \
                 InitEncryptionKey first"
            )),
        };
    };

    conversation_keys_from(request_id, ghostkey_fingerprint, &secret, peer_public_keys)
}

/// The conversation keys `secret` shares with each well-formed peer key.
fn conversation_keys_from(
    request_id: RequestId,
    ghostkey_fingerprint: &str,
    secret: &StaticSecret,
    peer_public_keys: &[Vec<u8>],
) -> HarvestDelegateResponse {
    let derived = peer_public_keys
        .iter()
        .filter_map(|peer| {
            let bytes: [u8; 32] = peer.as_slice().try_into().ok()?;
            let shared = secret.diffie_hellman(&PublicKey::from(bytes));
            // A low-order point makes the shared secret all zeros, so the
            // "conversation key" would be a constant anyone can compute --
            // and a message decrypted under it looks, to the seller, exactly
            // like one from a buyer who established a private channel.
            if !shared.was_contributory() {
                return None;
            }
            let shared = shared.to_bytes();
            Some(ConversationKey {
                peer_public_key: peer.clone(),
                buyer_to_seller: conversation_key_from_dh(&shared, MessageDirection::BuyerToSeller),
                seller_to_buyer: conversation_key_from_dh(&shared, MessageDirection::SellerToBuyer),
            })
        })
        .collect();

    HarvestDelegateResponse::ConversationKeys {
        request_id,
        ghostkey_fingerprint: ghostkey_fingerprint.to_string(),
        result: Ok(derived),
    }
}

// ---------------------------------------------------------------------------
// The buyer's half: conversation secrets that outlive a browser tab.
// ---------------------------------------------------------------------------

/// How many buyer conversations one node keeps, across every store.
///
/// # Why a COUNT is a real bound here, unlike in the mailbox
///
/// This repository has the count-cap-over-contract-controlled-values pattern
/// written up, and the reflex on seeing a count cap is to call it a fake
/// bound. It is worth saying why that reflex does not apply here rather than
/// making the next reader re-derive it.
///
/// That pattern bites when a count caps entries whose values are
/// **contract-controlled and variable** -- the mailbox, where `ciphertext`
/// was attacker-supplied and unbounded, so 512 entries meant nothing about
/// bytes. Here both halves are bounded:
///
/// * the VALUE is three 32-byte arrays and an `i64`, so its CBOR is a fixed
///   shape a caller cannot inflate;
/// * the KEY is `harvest:buyer_conv:` plus two base58 32-byte values, because
///   [`store_buyer_conversation`] refuses a `store_contract_id` that is not
///   32 bytes. Without that refusal the key would be caller-sized and this
///   cap would bound entries while bounding no bytes at all -- which is
///   exactly the pattern above. Pinned by
///   `a_store_id_that_is_not_a_contract_id_is_refused`.
///
/// So this is about 60 KiB at the cap, and the cap is what stops a page
/// opening conversations in a loop from growing the secret store without
/// limit.
pub(crate) const MAX_BUYER_CONVERSATIONS: usize = 256;

/// A contract instance id, which is what a store is named by.
const STORE_CONTRACT_ID_BYTES: usize = 32;

pub(crate) const BUYER_CONVERSATION_PREFIX_STR: &str = "harvest:buyer_conv:";

/// Every buyer conversation this delegate holds, whichever store it is with.
///
/// Under `harvest:` like everything else the delegate writes, because the
/// migration export is defined by that prefix. A re-key that left these
/// behind would destroy every buyer's ability to read a reply -- the same
/// loss this whole mechanism exists to prevent, arriving by another route.
/// Pinned by `buyer_conversations_are_under_the_exported_prefix`.
pub(crate) const BUYER_CONVERSATION_PREFIX: &[u8] = BUYER_CONVERSATION_PREFIX_STR.as_bytes();

/// Where one buyer conversation lives:
/// `harvest:buyer_conv:{store id}:{routing tag}`, both base58.
///
/// # Why the key names both halves
///
/// Because both are recoverable after a reload and nothing else is. The store
/// id is in the URL the buyer followed, and the tag is the buyer's ephemeral
/// public key, which every message in the conversation carries in the clear.
/// Naming them makes recall a prefix listing rather than a scan of every
/// secret the delegate holds.
///
/// The `:` terminator matters: it is not in the base58 alphabet, so one
/// store's prefix cannot be a prefix of another store's keys, and
/// [`list_buyer_conversations`] cannot hand back a neighbouring store's
/// conversations. Pinned by `conversations_are_scoped_to_their_store`.
///
/// **What this leaves behind is deliberate and is documented rather than
/// hidden.** The key records that this node held a conversation with that
/// store, so the record is a durable local artefact of who the buyer
/// contacted -- see `docs/messaging-privacy.md`. It is removable:
/// [`forget_buyer_conversation`] deletes the key outright rather than
/// emptying it.
pub(crate) fn buyer_conversation_key(
    store_contract_id: &[u8],
    buyer_public_key: &[u8; 32],
) -> Vec<u8> {
    let mut key = buyer_conversation_store_prefix(store_contract_id);
    key.extend_from_slice(bs58::encode(buyer_public_key).into_string().as_bytes());
    key
}

/// Every conversation held for ONE store.
fn buyer_conversation_store_prefix(store_contract_id: &[u8]) -> Vec<u8> {
    format!(
        "{BUYER_CONVERSATION_PREFIX_STR}{}:",
        bs58::encode(store_contract_id).into_string()
    )
    .into_bytes()
}

/// What is kept for one conversation.
///
/// The routing tag is NOT a field: it is the public half of `secret`, so
/// [`recall`] derives it. A stored copy would be a second source for one
/// value that could disagree with the key it is filed under, and a
/// conversation recalled under a tag no mailbox message carries would read as
/// an empty thread with nothing to explain it.
#[derive(serde::Serialize, serde::Deserialize, Clone, PartialEq, Debug)]
pub(crate) struct BuyerConversationRecord {
    /// The buyer's ephemeral X25519 secret. Prints as `redacted`; see
    /// [`ConversationSecret`].
    pub(crate) secret: ConversationSecret,
    /// The seller key this conversation was opened against. [`recall`]
    /// derives with THIS rather than with anything a caller supplies, so the
    /// recall path is not a Diffie-Hellman oracle against stored secrets.
    pub(crate) seller_public_key: [u8; 32],
    pub(crate) conversation_id: [u8; 32],
    /// Unix seconds, as the buyer's browser reported them, used only for
    /// eviction order. See `HarvestDelegateRequest::StoreBuyerConversation`
    /// for why the delegate does not read the host clock here.
    pub(crate) created_at: i64,
    /// Whether the buyer has said they hold a copy of this outside this node.
    ///
    /// # Why this is a field and not a key of its own
    ///
    /// The ghostkey vault keeps its equivalent as a separate secret
    /// (`gk:backedup:{fingerprint}`), and that shape is wrong here for a
    /// reason specific to what these records are. A marker keyed by store and
    /// tag would OUTLIVE the conversation it describes: forgetting a
    /// conversation would leave behind a key still naming the store, which is
    /// precisely the durable local record `forget_buyer_conversation` exists
    /// to remove. Inside the value it is deleted with the thing it describes,
    /// counts against the same cap, and cannot drift out of step with it.
    /// Pinned by `forgetting_a_conversation_leaves_no_backup_marker_behind`.
    ///
    /// `serde(default)` so a record written before this field existed decodes
    /// as not-backed-up, which is the safe direction: the warning appears
    /// until the buyer says otherwise.
    #[serde(default)]
    pub(crate) backed_up: bool,
    /// Whether this record arrived by IMPORT rather than being opened here.
    ///
    /// # Why this exists when `created_at` already orders eviction
    ///
    /// Because `created_at` is chosen by the other side. It travels inside
    /// the backup string and nothing signs it -- the same shape as the
    /// mailbox TTL that one forged timestamp emptied, and as the fold
    /// tie-break, both of which were fixed by ranking on something the other
    /// side cannot choose. This is that something: the delegate sets it from
    /// WHICH CALL arrived, so no string can claim it.
    ///
    /// It ranks an imported conversation below one opened here, which is the
    /// right way round: a restored conversation is one the buyer demonstrably
    /// holds a string for, and a locally-opened one may exist nowhere else.
    ///
    /// `serde(default)` -- false, "opened here" -- is the safe direction for
    /// a record written before the field existed: it is the harder one to
    /// evict.
    #[serde(default)]
    pub(crate) imported: bool,
}

/// Every conversation the delegate holds, with whichever store, as
/// `(key, record)`.
///
/// A key whose value does not decode is reported with `None` rather than
/// dropped: it still occupies a key, so the cap has to be able to see it --
/// and it is the first thing evicted, since it recalls nothing.
fn held_conversations<S: SecretStore>(
    store: &S,
) -> Vec<(Vec<u8>, Option<BuyerConversationRecord>)> {
    store
        .list_secrets(BUYER_CONVERSATION_PREFIX)
        .into_iter()
        .map(|key| {
            let record = store.get_secret(&key).and_then(|bytes| {
                harvest_common::from_cbor::<BuyerConversationRecord>(&bytes).ok()
            });
            (key, record)
        })
        .collect()
}

/// Keep a buyer's conversation, evicting the oldest if every slot is taken.
///
/// The routing tag is derived from the secret, so what is answered and what
/// is filed can never disagree about which conversation this is.
pub(crate) fn store_buyer_conversation<S: SecretStore + RemovableSecrets>(
    store: &mut S,
    request_id: RequestId,
    store_contract_id: &[u8],
    record: &BuyerConversationRecord,
) -> HarvestDelegateResponse {
    let stored = |result| HarvestDelegateResponse::BuyerConversationStored {
        request_id,
        result,
        evicted: Vec::new(),
    };

    if store_contract_id.len() != STORE_CONTRACT_ID_BYTES {
        return stored(Err(format!(
            "a store is named by a {STORE_CONTRACT_ID_BYTES}-byte contract id, and this one is \
             {} bytes -- refusing to keep a conversation under a name that is not a store",
            store_contract_id.len()
        )));
    }

    let bytes = match harvest_common::to_cbor(record) {
        Ok(bytes) => bytes,
        Err(e) => return stored(Err(format!("could not serialize the conversation: {e}"))),
    };

    let buyer_public_key = *PublicKey::from(&StaticSecret::from(record.secret.0)).as_bytes();
    let key = buyer_conversation_key(store_contract_id, &buyer_public_key);

    // Only a NEW key consumes a slot. Re-storing the same conversation --
    // which the UI does whenever it re-sends into a thread it already has --
    // must not evict anything.
    let mut evicted = Vec::new();
    if !store.has_secret(&key) {
        match make_room(store) {
            Ok(discarded) => evicted = discarded,
            // The eviction report travels with the failure too: whatever was
            // discarded is gone whether or not the write that followed
            // worked.
            Err(why) => {
                return HarvestDelegateResponse::BuyerConversationStored {
                    request_id,
                    result: Err(why),
                    evicted,
                }
            }
        }
    }

    let result = if store.set_secret(&key, &bytes) {
        Ok(())
    } else {
        // Reported rather than swallowed: the UI has already told the buyer
        // their message was sent, and a conversation that was not kept
        // becomes unreadable the moment the tab closes.
        Err(
            "could not keep this conversation -- the node refused the write, so a reply \
             will not be readable after this tab closes"
                .to_string(),
        )
    };
    HarvestDelegateResponse::BuyerConversationStored {
        request_id,
        result,
        evicted,
    }
}

/// Free a slot if every one is taken, and say what that cost.
///
/// Eviction rather than refusal, because refusing would mean the conversation
/// the buyer is having RIGHT NOW is the one that cannot be saved.
///
/// There is deliberately no age-based expiry anywhere here. That would be the
/// mailbox's TTL mistake at a higher cost: it would discard precisely the
/// capability the buyer needs later, at a time the buyer has no way to
/// predict.
///
/// # The order, and why `backed_up` comes before age
///
/// Ranked ascending by `(has no backup, age, key)`, so the FIRST things
/// discarded are the ones the buyer can get back:
///
/// 1. an entry that does not decode -- it recalls nothing, so discarding it
///    costs nothing;
/// 2. a conversation that arrived by IMPORT, which the buyer demonstrably
///    holds a string for;
/// 3. any other conversation the buyer holds a backup of;
/// 4. a conversation that exists on this node and nowhere else;
/// 5. within each of those, oldest first, then the lowest key so the choice
///    is deterministic rather than dependent on listing order.
///
/// **The import tier is not a refinement of the backed-up one.** `created_at`
/// travels inside the backup string and nothing signs it, so ordering by age
/// alone lets the other side decide which of the buyer's records goes first;
/// `imported` is set by the delegate from which call arrived, so no string
/// can claim it. Pinned by
/// `an_imported_conversation_is_evicted_before_one_opened_here`.
///
/// Age alone was not safe, and the way it failed is worth keeping: the cap is
/// global across every store and `created_at` arrives from the wire -- from
/// the browser when a conversation is opened, and **from the backup string on
/// the import path**, where nothing signs it. A buyer handed a backup by
/// somebody else could paste 253 records dated `i64::MAX`, fill the store to
/// its cap, and have the next conversation they opened silently destroy one
/// of their own. It composes the other way now: import marks what it restores
/// as backed up, which is true, and that is exactly what makes the attacker's
/// records the eligible ones. Pinned by
/// `a_conversation_that_exists_only_here_outlives_an_imported_one`.
fn make_room<S: SecretStore + RemovableSecrets>(
    store: &mut S,
) -> Result<Vec<EvictedConversation>, String> {
    let mut held = held_conversations(store);
    let mut evicted = Vec::new();
    while held.len() >= MAX_BUYER_CONVERSATIONS {
        let Some(victim) = held
            .iter()
            .enumerate()
            .min_by_key(|(_, (key, record))| {
                (
                    record.as_ref().map(|record| {
                        // 0 restorable from a string the buyer holds,
                        // 1 backed up some other way, 2 exists only here.
                        let tier = if !record.backed_up {
                            2
                        } else if record.imported {
                            0
                        } else {
                            1
                        };
                        (tier, record.created_at)
                    }),
                    key.clone(),
                )
            })
            .map(|(index, _)| index)
        else {
            // Unreachable while `held.len() >= MAX_BUYER_CONVERSATIONS`, and
            // a `break` rather than an `expect` so a future change to the cap
            // cannot turn this into a panic inside a delegate.
            break;
        };
        let (key, record) = held.remove(victim);
        if let Some(record) = &record {
            evicted.push(EvictedConversation {
                buyer_public_key: *PublicKey::from(&StaticSecret::from(record.secret.0)).as_bytes(),
                was_backed_up: record.backed_up,
            });
        }
        if !store.remove_secret(&key) {
            // Refusing to grow past the cap is the safe direction: the
            // alternative is an unbounded secret store on a node whose host
            // is already refusing writes.
            return Err(
                "could not make room for this conversation -- the node refused to remove an \
                 older one, so a reply will not be readable after this tab closes"
                    .to_string(),
            );
        }
    }
    Ok(evicted)
}

/// Recall every conversation stored for one store, as derived keys.
///
/// The keys are derived here, from the stored secret and the SELLER key the
/// conversation was opened against, so the secret never leaves. Deriving
/// against a caller-supplied key instead would make this a Diffie-Hellman
/// oracle against every secret the node holds.
pub(crate) fn list_buyer_conversations<S: SecretStore>(
    store: &S,
    request_id: RequestId,
    store_contract_id: &[u8],
) -> HarvestDelegateResponse {
    let prefix = buyer_conversation_store_prefix(store_contract_id);
    let conversations = store
        .list_secrets(&prefix)
        .into_iter()
        .filter_map(|key| store.get_secret(&key))
        .filter_map(|bytes| harvest_common::from_cbor::<BuyerConversationRecord>(&bytes).ok())
        .filter_map(|record| recall(&record))
        .collect();

    HarvestDelegateResponse::BuyerConversationList {
        request_id,
        store_contract_id: store_contract_id.to_vec(),
        conversations,
    }
}

/// One stored record as the two keys that read its thread.
fn recall(record: &BuyerConversationRecord) -> Option<RecalledConversation> {
    let secret = StaticSecret::from(record.secret.0);
    let shared = secret.diffie_hellman(&PublicKey::from(record.seller_public_key));
    // The same refusal as the seller's side: a low-order peer makes the
    // shared secret all zeros, so the "conversation key" would be a constant
    // anyone can compute.
    if !shared.was_contributory() {
        return None;
    }
    let shared = shared.to_bytes();

    Some(RecalledConversation {
        buyer_public_key: *PublicKey::from(&secret).as_bytes(),
        conversation_id: record.conversation_id,
        buyer_to_seller: conversation_key_from_dh(&shared, MessageDirection::BuyerToSeller),
        seller_to_buyer: conversation_key_from_dh(&shared, MessageDirection::SellerToBuyer),
        // From the STORED secret, not from the shared secret and not from
        // anything a caller supplies: the binding's whole value is that the
        // seller cannot compute it, and the shared secret is a value the
        // seller holds.
        order_binding: harvest_common::mailbox::order_binding_from_secret(&record.secret.0),
        created_at: record.created_at,
        imported: record.imported,
        backed_up: record.backed_up,
    })
}

/// Discard one conversation, permanently.
///
/// # Why this deletes rather than empties
///
/// This is the buyer's control over the record their node keeps of who they
/// contacted, and the key itself carries the store id. Emptying the value
/// would leave that key in place, so a "forget" that emptied would be a
/// control that lies: the conversation would stop being readable while the
/// evidence of it stayed. `SecretStore` cannot express deletion, which is why
/// this takes the extra [`RemovableSecrets`] bound -- see that trait for what
/// the node actually does with the request.
///
/// The answer is checked rather than assumed: the key is re-read afterwards
/// and a key that is still there is reported as a failure. A buyer stops
/// being careful on the strength of a control like this, so it must not
/// report a success it cannot stand behind.
pub(crate) fn forget_buyer_conversation<S: SecretStore + RemovableSecrets>(
    store: &mut S,
    request_id: RequestId,
    store_contract_id: &[u8],
    buyer_public_key: &[u8; 32],
) -> HarvestDelegateResponse {
    let key = buyer_conversation_key(store_contract_id, buyer_public_key);

    let result = if !store.has_secret(&key) {
        // Already gone. Reported as success: the buyer asked for it not to be
        // there, and it is not there.
        Ok(())
    } else if store.remove_secret(&key) && !store.has_secret(&key) {
        Ok(())
    } else {
        Err(
            "could not forget this conversation -- the node refused to remove it, so it is \
             still stored here"
                .to_string(),
        )
    };

    HarvestDelegateResponse::BuyerConversationForgotten { request_id, result }
}

// ---------------------------------------------------------------------------
// Backup: one conversation's secret, in a form the buyer can carry.
// ---------------------------------------------------------------------------

/// What a backup string starts with.
///
/// A prefix rather than a bare base58 blob so a paste that is not a Harvest
/// backup -- a ghostkey PEM, a store link, half a string -- is refused with a
/// sentence the buyer can act on instead of a decoding error.
///
/// **v2, and the bump is the point.** v1 carried a whole store's
/// conversations; this carries one. The version lives in the prefix so a
/// change of payload is a change of name, and a v1 string is refused as "not
/// one of ours" rather than decoding into something that no longer means what
/// it says. No v1 string was ever produced outside this repository's tests,
/// so there is deliberately no v1-reading code: a compatibility path for an
/// artefact that never existed would be untested code asserting a scenario
/// that cannot happen.
pub(crate) const BUYER_CONVERSATION_BACKUP_PREFIX: &str = "harvest-conv-backup-v2:";

/// The longest backup string this delegate will attempt to read.
///
/// # Why a length cap and not just "it will fail to decode"
///
/// Base58 decoding is **quadratic** in the length of the string, because it
/// is repeated big-integer division. Found by measurement rather than by
/// reading: a test that round-tripped 253 conversations took 72 seconds in a
/// debug build, and nothing in the code had a bound on how long a pasted
/// string could be. A megabyte of base58 would occupy the delegate for
/// minutes before failing.
///
/// The paste comes from a person, but not necessarily from a string they
/// produced -- the whole restore flow is "paste what you saved", and what
/// someone else hands them is equally paste-able. The origin gate stops
/// another web app calling this; it does not stop a string.
///
/// 4 KiB is about ten times an honest backup, which carries ONE conversation
/// and comes to just under 400 characters -- measured, after an earlier
/// version of this comment guessed 210 and was caught by review. Both the cap
/// and that figure are pinned:
/// `a_backup_string_longer_than_the_cap_is_refused_without_decoding_it` and
/// `an_honest_backup_is_far_inside_the_length_cap`, which asserts the real
/// size falls in a band so the number here cannot drift again.
pub(crate) const MAX_BACKUP_STRING_BYTES: usize = 4 * 1024;

/// One conversation, as it travels between two nodes.
///
/// # Why one and not a store's worth
///
/// A store-wide backup is too easy to leave out of date: taken on Monday,
/// silently incomplete on Tuesday, and nothing about the artefact says which
/// conversations existed when it was taken. The marker settles it -- a
/// `backed_up` flag set from a store-wide export would falsely cover a
/// conversation created after that export, which is the "cannot silence a
/// warning about a key it has no backup of" property defeated through
/// granularity rather than through permission. See
/// `HarvestDelegateRequest::ExportBuyerConversation` and
/// `docs/buyer-conversation-persistence.md`.
///
/// A buyer restoring a machine pastes several strings in a row; nothing here
/// is stateful between them.
#[derive(serde::Serialize, serde::Deserialize, Clone, PartialEq, Debug)]
pub(crate) struct BuyerConversationBackupV2 {
    /// Which store this conversation is with. In the backup rather than asked
    /// for on import, because a buyer restoring onto a new node has the
    /// string and nothing to relate it to.
    pub(crate) store_contract_id: [u8; 32],
    pub(crate) conversation: BuyerConversationRecord,
}

/// A backup as a string the buyer can paste.
///
/// Base58Check inside the prefix, which is this repository's convention for
/// anything a person handles, and which carries a checksum: a string that
/// lost its tail in a copy is refused here rather than restoring a
/// conversation with a corrupt secret at the moment the buyer believes they
/// have their recourse back.
pub(crate) fn encode_backup(backup: &BuyerConversationBackupV2) -> Result<String, String> {
    let bytes = harvest_common::to_cbor(backup)
        .map_err(|e| format!("could not encode this backup: {e}"))?;
    Ok(format!(
        "{BUYER_CONVERSATION_BACKUP_PREFIX}{}",
        bs58::encode(&bytes).with_check().into_string()
    ))
}

/// The reverse, refusing anything that is not one of ours.
///
/// Every refusal names what was expected, because the thing a buyer pastes
/// here is whatever was on their clipboard -- a store link, a ghostkey PEM,
/// half a backup -- and "invalid CBOR" tells them nothing they can act on.
pub(crate) fn decode_backup(backup: &str) -> Result<BuyerConversationBackupV2, String> {
    // Before the decode, not after: the decode is the expensive part, and its
    // cost grows with the square of the length. See
    // [`MAX_BACKUP_STRING_BYTES`].
    if backup.len() > MAX_BACKUP_STRING_BYTES {
        return Err(format!(
            "that is {} bytes, and a Harvest conversation backup is never more than \
             {MAX_BACKUP_STRING_BYTES} -- nothing was read",
            backup.len()
        ));
    }
    let body = backup
        .trim()
        .strip_prefix(BUYER_CONVERSATION_BACKUP_PREFIX)
        .ok_or_else(|| {
            format!(
                "that does not look like a Harvest conversation backup -- one starts with \
                 `{BUYER_CONVERSATION_BACKUP_PREFIX}`"
            )
        })?;
    let bytes = bs58::decode(body)
        .with_check(None)
        .into_vec()
        .map_err(|e| {
            format!(
                "that Harvest conversation backup is damaged -- it did not survive its own \
             checksum, so some of it was lost in copying ({e})"
            )
        })?;
    harvest_common::from_cbor::<BuyerConversationBackupV2>(&bytes)
        .map_err(|e| format!("that Harvest conversation backup could not be read: {e}"))
}

/// Hand back ONE conversation as a string the buyer can save.
pub(crate) fn export_buyer_conversation<S: SecretStore>(
    store: &S,
    request_id: RequestId,
    store_contract_id: &[u8],
    buyer_public_key: &[u8; 32],
) -> HarvestDelegateResponse {
    let exported = |result| HarvestDelegateResponse::BuyerConversationExported {
        request_id,
        store_contract_id: store_contract_id.to_vec(),
        buyer_public_key: *buyer_public_key,
        result,
    };

    let Ok(id) = <[u8; 32]>::try_from(store_contract_id) else {
        return exported(Err(format!(
            "a store is named by a {STORE_CONTRACT_ID_BYTES}-byte contract id, and this one is \
             {} bytes",
            store_contract_id.len()
        )));
    };

    let Some(conversation) = store
        .get_secret(&buyer_conversation_key(store_contract_id, buyer_public_key))
        .and_then(|bytes| harvest_common::from_cbor::<BuyerConversationRecord>(&bytes).ok())
    else {
        // Refused rather than answered as an empty string. An empty backup
        // looks exactly like a real one once it is saved, and the buyer finds
        // out it was empty at the moment they need it.
        return exported(Err(
            "this node does not hold that conversation, so there is nothing to back up".to_string(),
        ));
    };

    exported(
        encode_backup(&BuyerConversationBackupV2 {
            store_contract_id: id,
            conversation,
        })
        .map(BackupString),
    )
}

/// Take one saved backup and make its conversation readable here.
///
/// # Three outcomes, and why the held record always wins
///
/// * **Imported** -- not held here, now is.
/// * **AlreadyHeld** -- the held record is KEPT, not overwritten. Pasting a
///   backup onto the node that made it is the ordinary "restore everything"
///   gesture and must not be an error; and an imported record sharing a
///   routing tag can only DISAGREE with the held one if it was hand-built,
///   since the tag is the public half of the secret. A different
///   `conversation_id` under the same tag would make a readable thread stop
///   reading, silently, which is the worse of the two mistakes. The one
///   exception is a held record that does not decode: it reads nothing, so
///   keeping it would refuse a restore in favour of rubbish.
/// * **Refused** -- with the reason.
///
/// **At the cap this refuses rather than evicting**, which inverts what
/// storing does. The inversion is the point: the conversation being imported
/// is provably backed up, because the buyer is holding the string it came
/// from, while the conversation eviction would take may exist only here.
pub(crate) fn import_buyer_conversation<S: SecretStore + RemovableSecrets>(
    store: &mut S,
    request_id: RequestId,
    backup: &str,
) -> HarvestDelegateResponse {
    let imported =
        |result| HarvestDelegateResponse::BuyerConversationImported { request_id, result };

    let backup = match decode_backup(backup) {
        Ok(backup) => backup,
        Err(why) => return imported(Err(why)),
    };

    let record = backup.conversation;
    let store_contract_id = backup.store_contract_id.to_vec();
    let secret = StaticSecret::from(record.secret.0);
    let buyer_public_key = *PublicKey::from(&secret).as_bytes();
    let key = buyer_conversation_key(&backup.store_contract_id, &buyer_public_key);
    let refused = |why: String| {
        imported(Ok(ImportedConversation::Refused {
            store_contract_id: store_contract_id.clone(),
            buyer_public_key,
            why,
        }))
    };

    // A record whose keys cannot be derived would occupy a slot and recall
    // nothing, so it is refused where the buyer can see it rather than
    // accepted and silently invisible.
    if !secret
        .diffie_hellman(&PublicKey::from(record.seller_public_key))
        .was_contributory()
    {
        return refused(
            "this conversation's keys cannot be derived -- the seller key it names is not \
             usable, so it would read nothing"
                .to_string(),
        );
    }

    // Held AND readable is the case that is kept.
    let occupied = store.has_secret(&key);
    if occupied
        && store
            .get_secret(&key)
            .and_then(|bytes| harvest_common::from_cbor::<BuyerConversationRecord>(&bytes).ok())
            .is_some()
    {
        return imported(Ok(ImportedConversation::AlreadyHeld {
            store_contract_id,
            buyer_public_key,
        }));
    }

    if !occupied && held_conversations(store).len() >= MAX_BUYER_CONVERSATIONS {
        return refused(format!(
            "this node is full: it already keeps {MAX_BUYER_CONVERSATIONS} conversations, and \
             nothing was discarded to make room because what it holds may exist nowhere else. \
             Forget a conversation you no longer need and paste this again."
        ));
    }

    // Backed up by construction: the buyer is holding the string it came
    // from. Warning about it would teach them to ignore the warning.
    //
    // `imported` is set HERE and never taken from the string, because the
    // eviction order depends on it and the point of it is that the other side
    // cannot choose it -- unlike `created_at`, which travels in the backup.
    let restored = BuyerConversationRecord {
        backed_up: true,
        imported: true,
        ..record
    };
    let Ok(bytes) = harvest_common::to_cbor(&restored) else {
        return refused("this conversation could not be re-encoded".to_string());
    };
    if store.set_secret(&key, &bytes) {
        imported(Ok(ImportedConversation::Imported {
            store_contract_id,
            buyer_public_key,
        }))
    } else {
        refused(
            "the node refused the write, so this conversation is still not readable here"
                .to_string(),
        )
    }
}

/// Record that the buyer holds a copy of THIS conversation elsewhere.
///
/// `Ok(true)` when it is marked, `Ok(false)` when this node does not hold it
/// -- which is not an error and creates nothing. A write the node REFUSED is
/// an `Err`, because "not marked" and "could not mark" are different
/// situations and a boolean cannot tell them apart; it answered `Ok`
/// unconditionally until review, which made the caller's failure path dead
/// code.
///
/// One conversation, matching the export. Marking a SET would let one saved
/// string clear the warning on a conversation it does not contain.
pub(crate) fn mark_conversation_backed_up<S: SecretStore>(
    store: &mut S,
    request_id: RequestId,
    store_contract_id: &[u8],
    buyer_public_key: &[u8; 32],
) -> HarvestDelegateResponse {
    let key = buyer_conversation_key(store_contract_id, buyer_public_key);
    let result = match store
        .get_secret(&key)
        .and_then(|bytes| harvest_common::from_cbor::<BuyerConversationRecord>(&bytes).ok())
    {
        None => Ok(false),
        Some(record) if record.backed_up => Ok(true),
        Some(record) => {
            let marked = BuyerConversationRecord {
                backed_up: true,
                ..record
            };
            match harvest_common::to_cbor(&marked) {
                Ok(bytes) if store.set_secret(&key, &bytes) => Ok(true),
                _ => Err(
                    "the node refused to record that you have saved this, so it will keep \
                     warning you about it"
                        .to_string(),
                ),
            }
        }
    };

    HarvestDelegateResponse::BuyerConversationMarkedBackedUp {
        request_id,
        store_contract_id: store_contract_id.to_vec(),
        buyer_public_key: *buyer_public_key,
        result,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::MemSecrets;

    const FP: &str = "fp1";

    fn public_key(response: &HarvestDelegateResponse) -> Vec<u8> {
        match response {
            HarvestDelegateResponse::EncryptionKeyReady {
                x25519_public_key, ..
            } => x25519_public_key.clone(),
            other => panic!("expected an EncryptionKeyReady, got {other:?}"),
        }
    }

    fn keys(response: &HarvestDelegateResponse) -> Vec<ConversationKey> {
        match response {
            HarvestDelegateResponse::ConversationKeys { result, .. } => {
                result.clone().expect("derivation should have succeeded")
            }
            other => panic!("expected ConversationKeys, got {other:?}"),
        }
    }

    fn error_message(response: &HarvestDelegateResponse) -> String {
        match response {
            HarvestDelegateResponse::Error { message } => message.clone(),
            HarvestDelegateResponse::ConversationKeys { result, .. } => match result {
                Err(message) => message.clone(),
                Ok(keys) => panic!("expected a refusal, got {} key(s)", keys.len()),
            },
            other => panic!("expected an error, got {other:?}"),
        }
    }

    /// A key is minted once and then recalled.
    ///
    /// Re-minting is the failure that matters: the seller publishes the
    /// public half in their store info, and a second call answering a
    /// DIFFERENT key would leave every message already encrypted to the first
    /// one undecryptable, with nothing anywhere reporting a problem. The UI
    /// calls this on every connect, so "idempotent" is the normal path rather
    /// than an edge case.
    /// A recall-only request never mints: the UI asks this way before the
    /// delegate secret migration has run, so a key minted here cannot stand
    /// in front of the one being imported (harvest#123). Once a key exists,
    /// a recall answers it. Mutated red by minting on a recall.
    #[test]
    fn a_recall_never_mints_and_answers_an_existing_key() {
        let mut store = MemSecrets::default();
        match init_encryption_key(&mut store, FP, true) {
            HarvestDelegateResponse::EncryptionKeyAbsent {
                ghostkey_fingerprint,
            } => {
                assert_eq!(ghostkey_fingerprint, FP)
            }
            other => panic!("expected EncryptionKeyAbsent, got {other:?}"),
        }
        assert!(store.is_empty(), "a recall wrote a key");
        let minted = public_key(&init_encryption_key(&mut store, FP, false));
        assert_eq!(
            public_key(&init_encryption_key(&mut store, FP, true)),
            minted
        );
    }

    #[test]
    fn the_encryption_key_is_minted_once_and_then_recalled() {
        let mut store = MemSecrets::default();

        let first = public_key(&init_encryption_key(&mut store, FP, false));
        assert_eq!(first.len(), 32, "an X25519 public key is 32 bytes");
        assert_ne!(first, vec![0u8; 32], "the key must not be all zeros");

        let second = public_key(&init_encryption_key(&mut store, FP, false));
        assert_eq!(first, second, "a second call minted a different key");
    }

    /// Two identities on one node get different keys, so the test above is
    /// not passing because the "key" is a constant.
    #[test]
    fn two_identities_get_different_keys() {
        let mut store = MemSecrets::default();
        let one = public_key(&init_encryption_key(&mut store, "fp1", false));
        let two = public_key(&init_encryption_key(&mut store, "fp2", false));
        assert_ne!(one, two);
    }

    /// **A public key must never be handed back when its private half was not
    /// stored.**
    ///
    /// The seller publishes whatever comes back here into a signed
    /// `StoreInfoV1`, which is on the network permanently. If the write
    /// failed, every buyer who reads that store encrypts to a key nobody
    /// holds: their messages arrive, look fine to them, and the seller can
    /// never read one. Reporting the failure means the seller publishes no
    /// key and buyers are told messaging is unavailable, which is recoverable.
    #[test]
    fn a_failed_write_is_reported_rather_than_answered_with_a_key() {
        let mut store = MemSecrets::default();
        store.writes_fail = true;

        let message = error_message(&init_encryption_key(&mut store, FP, false));
        assert!(
            message.contains("could not"),
            "the refusal must say the key was not stored: {message}"
        );
        assert!(
            store.is_empty(),
            "precondition: the store really did refuse the write"
        );
    }

    /// The property the whole scheme rests on: the seller derives, from their
    /// long-term secret and the buyer's ephemeral public key, exactly the key
    /// the buyer derived from their ephemeral secret and the seller's
    /// published public key.
    ///
    /// If this ever stops holding, nothing errors. AES-GCM tags simply fail
    /// to verify and every message in every conversation reads as corrupt.
    #[test]
    fn the_seller_derives_the_key_the_buyer_derived() {
        let mut store = MemSecrets::default();
        let seller_public_bytes = public_key(&init_encryption_key(&mut store, FP, false));
        let seller_public: [u8; 32] = seller_public_bytes.clone().try_into().expect("32 bytes");

        // The buyer's side, computed the way `harvest-ui`'s
        // `messaging::EphemeralKeypair::derive_shared_key` computes it: X25519
        // against the seller's published key, then
        // `conversation_key_from_dh`.
        let buyer_secret = StaticSecret::from([42u8; 32]);
        let buyer_public = PublicKey::from(&buyer_secret);
        let shared = buyer_secret
            .diffie_hellman(&PublicKey::from(seller_public))
            .to_bytes();
        let buyers_write_key = conversation_key_from_dh(&shared, MessageDirection::BuyerToSeller);
        let buyers_read_key = conversation_key_from_dh(&shared, MessageDirection::SellerToBuyer);

        let derived = keys(&derive_conversation_keys(
            &store,
            7,
            FP,
            &[buyer_public.as_bytes().to_vec()],
            None,
        ));

        assert_eq!(derived.len(), 1);
        assert_eq!(
            derived[0].peer_public_key,
            buyer_public.as_bytes().to_vec(),
            "the answer must echo the key it was derived against"
        );
        assert_eq!(
            derived[0].buyer_to_seller, buyers_write_key,
            "the seller cannot read what the buyer wrote"
        );
        assert_eq!(
            derived[0].seller_to_buyer, buyers_read_key,
            "the buyer cannot read what the seller replies"
        );
        assert_ne!(
            derived[0].buyer_to_seller, derived[0].seller_to_buyer,
            "one key for both directions makes a copied message read as a reply"
        );
    }

    /// A store with its own key reads with the inbox key that key derives
    /// (harvest#93 phase 1b): a buyer who encrypted to the store's published
    /// inbox key is read, and the Ghost Key's per-device key is not used.
    /// A device without the store key is refused, not answered with the
    /// per-device key. Mutated red by ignoring `store_verifying_key`.
    #[test]
    fn a_store_key_reads_with_the_inbox_key_it_derives() {
        let mut store = MemSecrets::default();
        let device_public = public_key(&init_encryption_key(&mut store, FP, false));
        let store_sk = ed25519_dalek::SigningKey::from_bytes(&[0x5a; 32]);
        assert!(crate::store_keys::keep(&mut store, &store_sk));
        let inbox = PublicKey::from(&harvest_common::custody::inbox_secret(&store_sk));
        assert_ne!(inbox.as_bytes().to_vec(), device_public);

        let buyer_secret = StaticSecret::from([42u8; 32]);
        let buyer_public = PublicKey::from(&buyer_secret);
        let shared = buyer_secret.diffie_hellman(&inbox).to_bytes();
        let derived = keys(&derive_conversation_keys(
            &store,
            7,
            FP,
            &[buyer_public.as_bytes().to_vec()],
            Some(store_sk.verifying_key().to_bytes()),
        ));
        assert_eq!(
            derived[0].buyer_to_seller,
            conversation_key_from_dh(&shared, MessageDirection::BuyerToSeller)
        );

        let other = ed25519_dalek::SigningKey::from_bytes(&[0x5b; 32]);
        let message = error_message(&derive_conversation_keys(
            &store,
            8,
            FP,
            &[buyer_public.as_bytes().to_vec()],
            Some(other.verifying_key().to_bytes()),
        ));
        assert!(message.contains("store's key"), "{message}");
    }

    /// Answers are paired by peer key, not by position, and a malformed entry
    /// does not shift the others onto the wrong buyer.
    ///
    /// This is the mutation that matters: with positional correlation, one
    /// dropped entry silently hands buyer A's conversation key to buyer B's
    /// messages, and the symptom is "some messages will not decrypt" rather
    /// than anything that names the cause.
    #[test]
    fn a_malformed_peer_key_does_not_shift_the_others() {
        let mut store = MemSecrets::default();
        init_encryption_key(&mut store, FP, false);

        let a = PublicKey::from(&StaticSecret::from([1u8; 32]));
        let b = PublicKey::from(&StaticSecret::from([2u8; 32]));

        let all = keys(&derive_conversation_keys(
            &store,
            1,
            FP,
            &[a.as_bytes().to_vec(), b.as_bytes().to_vec()],
            None,
        ));
        let with_a_dud = keys(&derive_conversation_keys(
            &store,
            2,
            FP,
            &[
                a.as_bytes().to_vec(),
                vec![0u8; 5], // not a public key at all
                b.as_bytes().to_vec(),
            ],
            None,
        ));

        assert_eq!(all.len(), 2);
        assert_eq!(
            with_a_dud.len(),
            2,
            "the malformed entry should be dropped, not answered"
        );
        for expected in &all {
            let found = with_a_dud
                .iter()
                .find(|k| k.peer_public_key == expected.peer_public_key)
                .expect("every well-formed peer key must still be answered");
            assert_eq!(
                &found.buyer_to_seller, &expected.buyer_to_seller,
                "a key moved to another buyer"
            );
            assert_eq!(&found.seller_to_buyer, &expected.seller_to_buyer);
        }
    }

    /// A low-order peer point makes X25519 produce an all-zero shared secret,
    /// so the "conversation key" is a constant anyone can compute. Refusing
    /// it costs one branch.
    ///
    /// The damage is modest -- the mailbox is open-write, so an attacker can
    /// already deposit whatever they like -- but a message the seller decrypts
    /// under a key the whole world knows reads to them exactly like a message
    /// from a buyer who established a private channel, and that is a
    /// distinction the UI has no other way to draw.
    #[test]
    fn a_low_order_peer_key_is_refused() {
        let mut store = MemSecrets::default();
        init_encryption_key(&mut store, FP, false);

        let good = PublicKey::from(&StaticSecret::from([3u8; 32]));
        let derived = keys(&derive_conversation_keys(
            &store,
            1,
            FP,
            &[vec![0u8; 32], good.as_bytes().to_vec()],
            None,
        ));

        assert_eq!(
            derived.len(),
            1,
            "the all-zero point must not yield a conversation key"
        );
        assert_eq!(derived[0].peer_public_key, good.as_bytes().to_vec());
    }

    /// Whatever this module writes has to be under the prefix a migration
    /// export carries, or the seller's encryption key is silently left behind
    /// the next time the delegate re-keys -- and every buyer then encrypts to
    /// a published key whose private half is gone.
    ///
    /// Driven through the real writer rather than asserted against
    /// `handlers::all_secret_key_shapes`, which is a hand-maintained list and
    /// so cannot notice a key nobody added to it.
    ///
    /// Observed red on 2026-09-05 by changing `x25519_sk_key`'s prefix --
    /// under which `migration::tests::every_secret_the_delegate_writes_is_
    /// under_the_exported_prefix` stayed GREEN, because the list it reads had
    /// been updated to match. That is the gap this test closes.
    #[test]
    fn everything_this_module_writes_is_under_the_exported_prefix() {
        let mut store = MemSecrets::default();
        init_encryption_key(&mut store, FP, false);

        let everything = store.list_secrets(b"");
        assert!(
            !everything.is_empty(),
            "precondition: something was written"
        );
        for key in everything {
            assert!(
                key.starts_with(b"harvest:"),
                "the delegate wrote {}, which no export would carry",
                String::from_utf8_lossy(&key)
            );
        }
    }

    /// An identity with no key yet is told so, rather than being handed an
    /// empty list that reads as "this buyer sent nothing".
    #[test]
    fn deriving_without_a_key_is_an_error_not_an_empty_answer() {
        let store = MemSecrets::default();
        let peer = PublicKey::from(&StaticSecret::from([5u8; 32]));

        let message = error_message(&derive_conversation_keys(
            &store,
            1,
            FP,
            &[peer.as_bytes().to_vec()],
            None,
        ));
        assert!(
            message.contains("no encryption key"),
            "the error must say what is missing: {message}"
        );
    }
}

/// The buyer's conversation store: the thing that makes a reply readable
/// after the tab that sent the question is gone.
#[cfg(test)]
mod buyer_conversation_tests {
    use super::*;
    use crate::secrets::MemSecrets;

    const STORE: &[u8] = &[3u8; 32];
    const OTHER_STORE: &[u8] = &[4u8; 32];

    /// One buyer's side of a conversation, plus the seller who can read it.
    struct Opened {
        seller: StaticSecret,
        buyer_public_key: [u8; 32],
        record: BuyerConversationRecord,
    }

    fn open(seed: u8) -> Opened {
        let secret = StaticSecret::from(seed_bytes(seed as u32));
        let seller = StaticSecret::from([200u8.wrapping_sub(seed); 32]);
        Opened {
            buyer_public_key: *PublicKey::from(&secret).as_bytes(),
            record: BuyerConversationRecord {
                secret: ConversationSecret(secret.to_bytes()),
                seller_public_key: *PublicKey::from(&seller).as_bytes(),
                conversation_id: [seed; 32],
                created_at: 1_700_000_000 + seed as i64,
                backed_up: false,
                imported: false,
            },
            seller,
        }
    }

    /// A distinct 32-byte seed per index, so the cap test can build more than
    /// [`MAX_BUYER_CONVERSATIONS`] different buyers.
    fn seed_bytes(i: u32) -> [u8; 32] {
        let mut seed = [1u8; 32];
        seed[..4].copy_from_slice(&i.to_be_bytes());
        seed
    }

    fn stored(response: &HarvestDelegateResponse) -> &Result<(), String> {
        match response {
            HarvestDelegateResponse::BuyerConversationStored { result, .. } => result,
            other => panic!("expected BuyerConversationStored, got {other:?}"),
        }
    }

    fn forgotten(response: &HarvestDelegateResponse) -> &Result<(), String> {
        match response {
            HarvestDelegateResponse::BuyerConversationForgotten { result, .. } => result,
            other => panic!("expected BuyerConversationForgotten, got {other:?}"),
        }
    }

    fn listed(response: &HarvestDelegateResponse) -> Vec<RecalledConversation> {
        match response {
            HarvestDelegateResponse::BuyerConversationList { conversations, .. } => {
                conversations.clone()
            }
            other => panic!("expected BuyerConversationList, got {other:?}"),
        }
    }

    /// The whole point: a conversation stored now is recallable later, with
    /// the keys that read it.
    ///
    /// The keys are checked against what the SELLER derives, from the seller's
    /// own secret, rather than against the delegate's own arithmetic repeated
    /// -- a recalled conversation whose keys only agree with themselves would
    /// read nothing out of the mailbox.
    #[test]
    fn recall_answers_the_binding_the_shared_derivation_gives() {
        let opened = open(11);
        let back = recall(&opened.record).expect("a usable record recalls");

        assert_eq!(
            back.order_binding,
            harvest_common::mailbox::order_binding_from_secret(&opened.record.secret.0),
            "a drift here leaves a returning buyer unable to recognise their own commitment, \
             silently"
        );

        // Derived from the buyer's own secret, and NOT from the shared
        // secret: the seller holds the shared secret, and a binding they
        // could compute would let one commitment be published for every buyer
        // at once, which is the hole this closes.
        let shared = StaticSecret::from(opened.record.secret.0)
            .diffie_hellman(&PublicKey::from(opened.record.seller_public_key))
            .to_bytes();
        assert_ne!(
            back.order_binding,
            harvest_common::mailbox::order_binding_from_secret(&shared),
            "the seller must not be able to compute a buyer's binding"
        );
    }

    /// **Two buyers of the same seller get different bindings.**
    ///
    /// The property, stated where the delegate produces it, rather than left
    /// to the derivation's own test: this is what stops one published
    /// commitment being payable by everyone who was shown it.
    #[test]
    fn two_conversations_recall_different_bindings() {
        let one = open(12);
        let two = open(13);
        assert_ne!(
            recall(&one.record).expect("recalls").order_binding,
            recall(&two.record).expect("recalls").order_binding,
        );
    }

    #[test]
    fn a_stored_conversation_comes_back_with_usable_keys() {
        let mut store = MemSecrets::default();
        let opened = open(9);

        stored(&store_buyer_conversation(
            &mut store,
            1,
            STORE,
            &opened.record,
        ))
        .as_ref()
        .expect("must store");

        let back = listed(&list_buyer_conversations(&store, 1, STORE));
        assert_eq!(back.len(), 1);
        assert_eq!(back[0].conversation_id, opened.record.conversation_id);
        assert_eq!(back[0].created_at, opened.record.created_at);

        // The routing tag has to be the one the mailbox carries, which is the
        // public half of the stored secret.
        assert_eq!(back[0].buyer_public_key, opened.buyer_public_key);

        // And the order binding has to be the shared derivation over the
        // STORED secret. See `recall_answers_the_binding_the_shared_derivation_gives`
        // for why this is the half that matters.
        assert_eq!(
            back[0].order_binding,
            harvest_common::mailbox::order_binding_from_secret(&opened.record.secret.0)
        );

        let shared = opened
            .seller
            .diffie_hellman(&PublicKey::from(opened.buyer_public_key))
            .to_bytes();
        assert_eq!(
            back[0].buyer_to_seller,
            conversation_key_from_dh(&shared, MessageDirection::BuyerToSeller)
        );
        assert_eq!(
            back[0].seller_to_buyer,
            conversation_key_from_dh(&shared, MessageDirection::SellerToBuyer)
        );
    }

    /// **The secret itself never comes back.**
    ///
    /// Recall answers derived keys, the same shape as the seller's side. A
    /// secret handed to the UI on every reload would be a secret in every
    /// browser log and bug report, for no gain: the UI needs the keys.
    #[test]
    fn the_secret_never_leaves_the_delegate() {
        let mut store = MemSecrets::default();
        let opened = open(11);
        store_buyer_conversation(&mut store, 1, STORE, &opened.record);

        let response = list_buyer_conversations(&store, 1, STORE);
        let encoded = harvest_common::to_cbor(&response).expect("cbor");
        let secret = opened.record.secret.0;
        assert!(
            !encoded.windows(secret.len()).any(|window| window == secret),
            "the conversation secret appeared in the recall answer"
        );
    }

    /// Conversations are scoped to their store, so browsing one store does
    /// not hand back the keys for another.
    #[test]
    fn conversations_are_scoped_to_their_store() {
        let mut store = MemSecrets::default();
        let here = open(21);
        let elsewhere = open(22);

        store_buyer_conversation(&mut store, 1, STORE, &here.record);
        store_buyer_conversation(&mut store, 2, OTHER_STORE, &elsewhere.record);

        let recalled = listed(&list_buyer_conversations(&store, 1, STORE));
        assert_eq!(recalled.len(), 1);
        assert_eq!(recalled[0].buyer_public_key, here.buyer_public_key);
    }

    /// **A failed write is reported, not swallowed.**
    ///
    /// By the time this runs the UI has told the buyer their message was
    /// sent. If the secret was not kept, the seller's reply becomes
    /// unreadable after a reload -- and that is exactly the failure this
    /// whole mechanism exists to prevent, so it must not happen quietly.
    #[test]
    fn a_failed_write_is_reported() {
        let mut store = MemSecrets::refusing_writes();
        let opened = open(13);

        let response = store_buyer_conversation(&mut store, 7, STORE, &opened.record);
        let message = stored(&response)
            .as_ref()
            .expect_err("a refused write must be reported");
        assert!(
            message.contains("readable"),
            "the error must say what the buyer loses: {message}"
        );
    }

    /// **A store id that is not a contract id is refused, and nothing is
    /// written.**
    ///
    /// The id is base58-encoded into the secret's key, so a caller-sized id
    /// would be a caller-sized key -- and then [`MAX_BUYER_CONVERSATIONS`]
    /// would bound entries while bounding no bytes, which is the exact
    /// count-cap-over-variable-values trap this codebase has been bitten by.
    #[test]
    fn a_store_id_that_is_not_a_contract_id_is_refused() {
        let mut store = MemSecrets::default();
        let opened = open(29);

        let response = store_buyer_conversation(&mut store, 1, &[7u8; 4096], &opened.record);
        let message = stored(&response)
            .as_ref()
            .expect_err("an oversized store id must be refused");
        assert!(message.contains("32-byte"), "{message}");
        assert!(store.is_empty(), "a refused store id still wrote a secret");
    }

    /// **Forgetting leaves NOTHING behind, not an emptied value.**
    ///
    /// The key names the store, so a "forget" that emptied the value would
    /// stop the conversation being readable while leaving a durable record
    /// that this node talked to that store. A control that lies about what it
    /// does is worse than no control, because the buyer stops being careful
    /// on the strength of it.
    #[test]
    fn a_forgotten_conversation_leaves_nothing_behind() {
        let mut store = MemSecrets::default();
        let opened = open(15);
        store_buyer_conversation(&mut store, 1, STORE, &opened.record);
        assert_eq!(listed(&list_buyer_conversations(&store, 1, STORE)).len(), 1);

        forgotten(&forget_buyer_conversation(
            &mut store,
            2,
            STORE,
            &opened.buyer_public_key,
        ))
        .as_ref()
        .expect("must forget");

        assert!(
            listed(&list_buyer_conversations(&store, 1, STORE)).is_empty(),
            "a forgotten conversation was still recalled"
        );
        assert!(
            store.list_secrets(BUYER_CONVERSATION_PREFIX).is_empty(),
            "the key survived the forget, so the node still records which store this was: {:?}",
            store
                .list_secrets(BUYER_CONVERSATION_PREFIX)
                .iter()
                .map(|key| String::from_utf8_lossy(key).into_owned())
                .collect::<Vec<_>>()
        );
    }

    /// A removal the node refuses is reported as a failure, and the
    /// conversation is still there afterwards.
    ///
    /// The buyer must not be told a record is gone while it is on their disk.
    #[test]
    fn a_refused_removal_is_not_reported_as_forgotten() {
        let mut store = MemSecrets::default();
        let opened = open(16);
        store_buyer_conversation(&mut store, 1, STORE, &opened.record);
        store.removals_fail = true;

        let response = forget_buyer_conversation(&mut store, 2, STORE, &opened.buyer_public_key);
        let message = forgotten(&response)
            .as_ref()
            .expect_err("a refused removal must be reported");
        assert!(message.contains("still stored"), "{message}");
        assert_eq!(
            listed(&list_buyer_conversations(&store, 1, STORE)).len(),
            1,
            "the conversation should still be there, since removal failed"
        );
    }

    /// Forgetting one conversation forgets exactly that one.
    #[test]
    fn forgetting_one_conversation_leaves_the_others() {
        let mut store = MemSecrets::default();
        let kept = open(31);
        let discarded = open(32);
        let elsewhere = open(33);
        store_buyer_conversation(&mut store, 1, STORE, &kept.record);
        store_buyer_conversation(&mut store, 2, STORE, &discarded.record);
        store_buyer_conversation(&mut store, 3, OTHER_STORE, &elsewhere.record);

        forgotten(&forget_buyer_conversation(
            &mut store,
            4,
            STORE,
            &discarded.buyer_public_key,
        ))
        .as_ref()
        .expect("must forget");

        let here = listed(&list_buyer_conversations(&store, 1, STORE));
        assert_eq!(here.len(), 1);
        assert_eq!(here[0].buyer_public_key, kept.buyer_public_key);
        assert_eq!(
            listed(&list_buyer_conversations(&store, 1, OTHER_STORE)).len(),
            1,
            "another store's conversation was forgotten too"
        );
    }

    /// Forgetting something that is not there is success: the buyer asked for
    /// it not to be there, and it is not there.
    #[test]
    fn forgetting_a_conversation_that_is_not_there_is_success() {
        let mut store = MemSecrets::default();
        forgotten(&forget_buyer_conversation(&mut store, 1, STORE, &[9u8; 32]))
            .as_ref()
            .expect("must report success");
    }

    /// **The cap bounds the store, and evicts the OLDEST.**
    ///
    /// Eviction rather than refusal: refusing would mean the conversation the
    /// buyer is having right now is the one that cannot be saved, which is
    /// the wrong one to lose.
    #[test]
    fn the_cap_bounds_the_store_and_evicts_the_oldest() {
        let mut store = MemSecrets::default();

        let mut oldest = [0u8; 32];
        let mut newest = [0u8; 32];
        for i in 0..(MAX_BUYER_CONVERSATIONS + 8) {
            let secret = StaticSecret::from(seed_bytes(i as u32));
            let buyer_public_key = *PublicKey::from(&secret).as_bytes();
            let record = BuyerConversationRecord {
                secret: ConversationSecret(secret.to_bytes()),
                seller_public_key: [7u8; 32],
                conversation_id: [1u8; 32],
                created_at: 1_700_000_000 + i as i64,
                backed_up: false,
                imported: false,
            };
            if i == 0 {
                oldest = buyer_public_key;
            }
            newest = buyer_public_key;
            stored(&store_buyer_conversation(
                &mut store, i as u64, STORE, &record,
            ))
            .as_ref()
            .expect("must store");
        }

        let kept = listed(&list_buyer_conversations(&store, 1, STORE));
        assert_eq!(
            kept.len(),
            MAX_BUYER_CONVERSATIONS,
            "the cap did not bound the store"
        );
        assert!(
            !kept.iter().any(|c| c.buyer_public_key == oldest),
            "the oldest conversation should have been the one evicted"
        );
        // And the newest survives, so the assertion above is not passing
        // because everything was discarded.
        assert!(
            kept.iter().any(|c| c.buyer_public_key == newest),
            "the conversation the buyer is having right now was the one dropped"
        );
    }

    /// Re-storing a conversation the delegate already holds evicts nothing.
    ///
    /// The UI re-sends the same conversation whenever the buyer writes into a
    /// thread it already has, so a full store would otherwise shed one real
    /// conversation per message sent.
    ///
    /// # The fixture re-stores the NEWEST, and that is the whole test
    ///
    /// It re-stored the OLDEST until this was reviewed, and that could not
    /// observe the failure it describes: the oldest held conversation is also
    /// the eviction victim, so with the guard deleted `make_room` evicted
    /// exactly the record about to be re-written and the eviction cancelled
    /// itself out. The suite stayed green with the guard gone.
    ///
    /// The newest is also the realistic case: it is the thread the buyer is
    /// actively writing into, so it is the one the UI re-sends.
    #[test]
    fn re_storing_a_held_conversation_evicts_nothing() {
        let mut store = MemSecrets::default();
        let mut oldest = [0u8; 32];
        let mut newest = [0u8; 32];
        for i in 0..MAX_BUYER_CONVERSATIONS {
            let secret = StaticSecret::from(seed_bytes(i as u32));
            if i == 0 {
                oldest = *PublicKey::from(&secret).as_bytes();
            }
            newest = *PublicKey::from(&secret).as_bytes();
            let record = BuyerConversationRecord {
                secret: ConversationSecret(secret.to_bytes()),
                seller_public_key: [7u8; 32],
                conversation_id: [1u8; 32],
                created_at: 1_700_000_000 + i as i64,
                backed_up: false,
                imported: false,
            };
            store_buyer_conversation(&mut store, i as u64, STORE, &record);
        }
        assert_eq!(
            listed(&list_buyer_conversations(&store, 1, STORE)).len(),
            MAX_BUYER_CONVERSATIONS
        );

        // The NEWEST one again: the active thread, and NOT the record an
        // eviction would take.
        let secret = StaticSecret::from(seed_bytes(MAX_BUYER_CONVERSATIONS as u32 - 1));
        let record = BuyerConversationRecord {
            secret: ConversationSecret(secret.to_bytes()),
            seller_public_key: [7u8; 32],
            conversation_id: [2u8; 32],
            created_at: 1_700_000_000 + MAX_BUYER_CONVERSATIONS as i64 - 1,
            backed_up: false,
            imported: false,
        };
        stored(&store_buyer_conversation(&mut store, 999, STORE, &record))
            .as_ref()
            .expect("must store");

        let kept = listed(&list_buyer_conversations(&store, 1, STORE));
        assert_eq!(
            kept.len(),
            MAX_BUYER_CONVERSATIONS,
            "re-storing a held conversation changed how many are held"
        );
        assert!(
            kept.iter().any(|c| c.buyer_public_key == oldest),
            "re-sending into the active thread shed a real conversation"
        );
        assert!(kept.iter().any(|c| c.buyer_public_key == newest));
    }

    /// An entry whose value does not decode is evicted before a real one.
    ///
    /// It recalls nothing, so discarding it costs nothing -- and it still
    /// occupies a key, so something has to be able to reclaim it or the cap
    /// slowly fills with rubbish that cannot be read or removed.
    #[test]
    fn an_undecodable_entry_is_evicted_before_a_real_one() {
        let mut store = MemSecrets::default();
        let junk = buyer_conversation_key(STORE, &[0xAAu8; 32]);
        store.set_secret(&junk, b"not a conversation");

        let mut oldest = [0u8; 32];
        for i in 0..(MAX_BUYER_CONVERSATIONS - 1) {
            let secret = StaticSecret::from(seed_bytes(i as u32));
            if i == 0 {
                oldest = *PublicKey::from(&secret).as_bytes();
            }
            let record = BuyerConversationRecord {
                secret: ConversationSecret(secret.to_bytes()),
                seller_public_key: [7u8; 32],
                conversation_id: [1u8; 32],
                created_at: 1_700_000_000 + i as i64,
                backed_up: false,
                imported: false,
            };
            store_buyer_conversation(&mut store, i as u64, STORE, &record);
        }

        // One more, which must displace the junk rather than a conversation.
        let secret = StaticSecret::from(seed_bytes(9_000));
        let record = BuyerConversationRecord {
            secret: ConversationSecret(secret.to_bytes()),
            seller_public_key: [7u8; 32],
            conversation_id: [1u8; 32],
            created_at: 1_800_000_000,
            backed_up: false,
            imported: false,
        };
        stored(&store_buyer_conversation(&mut store, 1, STORE, &record))
            .as_ref()
            .expect("must store");

        assert!(
            !store
                .list_secrets(BUYER_CONVERSATION_PREFIX)
                .contains(&junk),
            "the undecodable entry survived"
        );
        assert!(
            listed(&list_buyer_conversations(&store, 1, STORE))
                .iter()
                .any(|c| c.buyer_public_key == oldest),
            "a real conversation was evicted while rubbish was kept"
        );
    }

    /// Everything this writes is under the exported prefix, so a delegate
    /// re-key carries it. Without that, a re-key destroys every buyer's
    /// ability to read a reply -- the same loss the whole mechanism exists to
    /// prevent, arriving by a different route.
    #[test]
    fn buyer_conversations_are_under_the_exported_prefix() {
        let mut store = MemSecrets::default();
        let opened = open(17);
        store_buyer_conversation(&mut store, 1, STORE, &opened.record);

        let everything = store.list_secrets(b"");
        assert!(!everything.is_empty(), "precondition");
        for key in everything {
            assert!(
                key.starts_with(b"harvest:"),
                "the delegate wrote {}, which no export would carry",
                String::from_utf8_lossy(&key)
            );
        }
    }
}

/// Backup: carrying ONE conversation to another node, and knowing whether it
/// exists in only one place.
#[cfg(test)]
mod buyer_conversation_backup_tests {
    use super::*;
    use crate::secrets::MemSecrets;

    const STORE: &[u8] = &[3u8; 32];
    const OTHER_STORE: &[u8] = &[4u8; 32];

    fn seed_bytes(i: u32) -> [u8; 32] {
        let mut seed = [1u8; 32];
        seed[..4].copy_from_slice(&i.to_be_bytes());
        seed
    }

    /// One conversation, and the tag it is filed under.
    fn conversation(seed: u32) -> ([u8; 32], BuyerConversationRecord) {
        let secret = StaticSecret::from(seed_bytes(seed));
        (
            *PublicKey::from(&secret).as_bytes(),
            BuyerConversationRecord {
                secret: ConversationSecret(secret.to_bytes()),
                seller_public_key: *PublicKey::from(&StaticSecret::from([9u8; 32])).as_bytes(),
                conversation_id: [seed as u8; 32],
                created_at: 1_700_000_000 + seed as i64,
                backed_up: false,
                imported: false,
            },
        )
    }

    fn stored(response: &HarvestDelegateResponse) -> &Result<(), String> {
        match response {
            HarvestDelegateResponse::BuyerConversationStored { result, .. } => result,
            other => panic!("expected BuyerConversationStored, got {other:?}"),
        }
    }

    fn exported(response: &HarvestDelegateResponse) -> &Result<BackupString, String> {
        match response {
            HarvestDelegateResponse::BuyerConversationExported { result, .. } => result,
            other => panic!("expected BuyerConversationExported, got {other:?}"),
        }
    }

    fn imported(response: &HarvestDelegateResponse) -> &Result<ImportedConversation, String> {
        match response {
            HarvestDelegateResponse::BuyerConversationImported { result, .. } => result,
            other => panic!("expected BuyerConversationImported, got {other:?}"),
        }
    }

    fn marked(response: &HarvestDelegateResponse) -> &Result<bool, String> {
        match response {
            HarvestDelegateResponse::BuyerConversationMarkedBackedUp { result, .. } => result,
            other => panic!("expected BuyerConversationMarkedBackedUp, got {other:?}"),
        }
    }

    fn listed(response: &HarvestDelegateResponse) -> Vec<RecalledConversation> {
        match response {
            HarvestDelegateResponse::BuyerConversationList { conversations, .. } => {
                conversations.clone()
            }
            other => panic!("expected BuyerConversationList, got {other:?}"),
        }
    }

    fn export(store: &MemSecrets, store_contract_id: &[u8], tag: &[u8; 32]) -> String {
        exported(&export_buyer_conversation(store, 1, store_contract_id, tag))
            .as_ref()
            .expect("must export")
            .0
            .clone()
    }

    /// **The whole point: a conversation carried to another node reads its
    /// thread there.**
    ///
    /// Two independent stores, as two machines would be. The keys the second
    /// one derives must be the ones the SELLER derives, or the restored
    /// conversation reads nothing and the buyer is no better off than before
    /// they saved anything.
    #[test]
    fn a_conversation_carried_to_another_node_reads_its_thread() {
        let mut laptop = MemSecrets::default();
        let (tag, record) = conversation(1);
        store_buyer_conversation(&mut laptop, 1, STORE, &record);

        let backup = export(&laptop, STORE, &tag);

        let mut phone = MemSecrets::default();
        match imported(&import_buyer_conversation(&mut phone, 2, &backup))
            .as_ref()
            .expect("must import")
        {
            ImportedConversation::Imported {
                store_contract_id,
                buyer_public_key,
            } => {
                assert_eq!(store_contract_id, STORE);
                assert_eq!(buyer_public_key, &tag);
            }
            other => panic!("expected Imported, got {other:?}"),
        }

        let here = listed(&list_buyer_conversations(&phone, 1, STORE));
        let there = listed(&list_buyer_conversations(&laptop, 1, STORE));
        assert_eq!(here.len(), 1);
        assert_eq!(
            here[0].buyer_to_seller, there[0].buyer_to_seller,
            "the restored conversation derives different keys, so it reads nothing"
        );
        assert_eq!(here[0].seller_to_buyer, there[0].seller_to_buyer);
        assert_eq!(here[0].conversation_id, there[0].conversation_id);
        assert_eq!(
            here[0].created_at, there[0].created_at,
            "a restored conversation must keep its age, or eviction order is wrong on the new node"
        );
    }

    /// A backup names itself, so a paste that is not one is refused with
    /// something the buyer can act on -- **including a v1 string**, which
    /// carried a whole store and means something this build does not.
    #[test]
    fn a_paste_that_is_not_a_backup_is_refused_by_name() {
        let mut store = MemSecrets::default();
        for junk in [
            "",
            "hello",
            "-----BEGIN GHOSTKEY CERTIFICATE-----",
            "harvest-conv-backup-v1:abc",
            "harvest-conv-backup-v3:abc",
        ] {
            let response = import_buyer_conversation(&mut store, 1, junk);
            let message = imported(&response).as_ref().expect_err("must refuse");
            assert!(
                message.contains("Harvest conversation backup"),
                "the refusal must name what was expected, for {junk:?}: {message}"
            );
        }
        assert!(store.is_empty(), "a refused paste wrote something");
    }

    /// **A truncated backup is refused rather than half-imported.**
    ///
    /// The string is long, unremarkable and copied by hand, so losing the end
    /// of it is the ordinary accident. The checksum is what turns that into a
    /// refusal instead of a conversation restored with a corrupt secret --
    /// which would read nothing, at a moment the buyer believes they have
    /// recovered their recourse.
    #[test]
    fn a_truncated_backup_is_refused() {
        let mut laptop = MemSecrets::default();
        let (tag, record) = conversation(2);
        store_buyer_conversation(&mut laptop, 1, STORE, &record);
        let backup = export(&laptop, STORE, &tag);

        let mut phone = MemSecrets::default();
        let truncated = &backup[..backup.len() - 4];
        imported(&import_buyer_conversation(&mut phone, 2, truncated))
            .as_ref()
            .expect_err("a truncated backup must be refused");
        assert!(phone.is_empty(), "a truncated backup wrote something");

        // And the whole string still works, so the refusal above is about the
        // truncation and not about the format.
        imported(&import_buyer_conversation(&mut phone, 3, &backup))
            .as_ref()
            .expect("the untruncated backup must import");
    }

    /// **A backup carries ONE conversation**, not everything this node holds
    /// with that store, and not another store's.
    ///
    /// This is the change Ian asked for: a store-wide string is silently
    /// incomplete the moment a new conversation is opened, and the buyer has
    /// no way to see that from the artefact.
    #[test]
    fn a_backup_carries_one_conversation() {
        let mut store = MemSecrets::default();
        let (wanted, wanted_record) = conversation(3);
        let (sibling, sibling_record) = conversation(4);
        let (_, elsewhere) = conversation(5);
        store_buyer_conversation(&mut store, 1, STORE, &wanted_record);
        store_buyer_conversation(&mut store, 2, STORE, &sibling_record);
        store_buyer_conversation(&mut store, 3, OTHER_STORE, &elsewhere);

        let backup = export(&store, STORE, &wanted);
        let mut fresh = MemSecrets::default();
        import_buyer_conversation(&mut fresh, 4, &backup);

        let restored = listed(&list_buyer_conversations(&fresh, 1, STORE));
        assert_eq!(
            restored.len(),
            1,
            "the backup carried more than one conversation"
        );
        assert_eq!(restored[0].buyer_public_key, wanted);
        assert_ne!(restored[0].buyer_public_key, sibling);
        assert!(
            listed(&list_buyer_conversations(&fresh, 1, OTHER_STORE)).is_empty(),
            "the backup carried another store's conversation"
        );
    }

    /// **Importing a conversation this node already holds keeps the held
    /// one.**
    ///
    /// Pasting a backup onto the node that made it is ordinary, so it must
    /// not be an error. Overwriting is the other tempting answer and is
    /// worse: the held record is the one this node's thread is being read
    /// with, and an imported record with the same routing tag can only DIFFER
    /// if it was hand-built -- a different `conversation_id` under the same
    /// tag would make a readable thread stop reading, silently.
    #[test]
    fn importing_a_held_conversation_keeps_the_held_one() {
        let mut store = MemSecrets::default();
        let (tag, record) = conversation(5);
        store_buyer_conversation(&mut store, 1, STORE, &record);
        let backup = export(&store, STORE, &tag);

        // A hand-built backup naming the same conversation with a different
        // id, which is the only way the two can disagree.
        let hostile = encode_backup(&BuyerConversationBackupV2 {
            store_contract_id: [3u8; 32],
            conversation: BuyerConversationRecord {
                conversation_id: [0xEE; 32],
                created_at: 1,
                ..record.clone()
            },
        })
        .expect("encode");

        for paste in [backup, hostile] {
            match imported(&import_buyer_conversation(&mut store, 2, &paste))
                .as_ref()
                .expect("must not be an error")
            {
                ImportedConversation::AlreadyHeld {
                    buyer_public_key, ..
                } => assert_eq!(buyer_public_key, &tag),
                other => panic!("expected AlreadyHeld, got {other:?}"),
            }
        }

        let kept = listed(&list_buyer_conversations(&store, 1, STORE));
        assert_eq!(kept.len(), 1);
        assert_eq!(
            kept[0].conversation_id, record.conversation_id,
            "an imported record overwrote the one this node reads its thread with"
        );
    }

    /// A held entry whose value does not decode IS replaced, because it reads
    /// nothing -- keeping it would refuse a restore in favour of rubbish.
    #[test]
    fn importing_over_an_undecodable_entry_restores_it() {
        let mut laptop = MemSecrets::default();
        let (tag, record) = conversation(6);
        store_buyer_conversation(&mut laptop, 1, STORE, &record);
        let backup = export(&laptop, STORE, &tag);

        let mut phone = MemSecrets::default();
        phone.set_secret(&buyer_conversation_key(STORE, &tag), b"corrupt");

        assert!(matches!(
            imported(&import_buyer_conversation(&mut phone, 2, &backup))
                .as_ref()
                .expect("must import"),
            ImportedConversation::Imported { .. }
        ));
        assert_eq!(listed(&list_buyer_conversations(&phone, 1, STORE)).len(), 1);
    }

    /// **At the cap, an import refuses and says why.**
    ///
    /// The opposite of what STORING does, and deliberately: the conversation
    /// being imported is provably backed up -- the buyer is holding the
    /// string -- while the conversation eviction would take may exist only
    /// here. So the safe direction inverts.
    #[test]
    fn an_import_at_the_cap_refuses_rather_than_evicting() {
        let mut phone = MemSecrets::default();
        let mut oldest = [0u8; 32];
        for i in 0..MAX_BUYER_CONVERSATIONS {
            let (tag, record) = conversation(1_000 + i as u32);
            if i == 0 {
                oldest = tag;
            }
            store_buyer_conversation(&mut phone, i as u64, STORE, &record);
        }

        let mut laptop = MemSecrets::default();
        let (carried, record) = conversation(7);
        store_buyer_conversation(&mut laptop, 1, STORE, &record);
        let backup = export(&laptop, STORE, &carried);

        match imported(&import_buyer_conversation(&mut phone, 2, &backup))
            .as_ref()
            .expect("a full node is not an error")
        {
            ImportedConversation::Refused {
                buyer_public_key,
                why,
                ..
            } => {
                assert_eq!(buyer_public_key, &carried);
                assert!(why.contains("full"), "the refusal must say why: {why}");
            }
            other => panic!("expected Refused, got {other:?}"),
        }
        assert!(
            listed(&list_buyer_conversations(&phone, 1, STORE))
                .iter()
                .any(|c| c.buyer_public_key == oldest),
            "an import evicted a conversation that may exist only on this node"
        );
    }

    /// **An imported conversation is already backed up**, because the buyer
    /// is holding the string it came from. Warning about it would train them
    /// to ignore the warning.
    #[test]
    fn an_imported_conversation_is_marked_as_backed_up() {
        let mut laptop = MemSecrets::default();
        let (tag, record) = conversation(8);
        store_buyer_conversation(&mut laptop, 1, STORE, &record);
        let backup = export(&laptop, STORE, &tag);

        let mut phone = MemSecrets::default();
        import_buyer_conversation(&mut phone, 2, &backup);
        let restored = listed(&list_buyer_conversations(&phone, 1, STORE));
        assert!(
            restored[0].backed_up,
            "a conversation the buyer just pasted in was reported as existing in one place only"
        );
        assert!(
            restored[0].imported,
            "a restored conversation must be recorded as restored: the eviction order depends \
             on it, and it is the one ordering input the other side cannot choose"
        );
    }

    /// A freshly opened conversation is NOT backed up, and stays that way
    /// until the buyer says otherwise.
    ///
    /// Exporting is not saving: a buyer who opens the panel, reads the
    /// string, and closes the tab has saved nothing.
    #[test]
    fn a_new_conversation_is_not_backed_up_and_exporting_does_not_change_that() {
        let mut store = MemSecrets::default();
        let (tag, record) = conversation(9);
        store_buyer_conversation(&mut store, 1, STORE, &record);
        assert!(!listed(&list_buyer_conversations(&store, 1, STORE))[0].backed_up);

        let _ = export(&store, STORE, &tag);
        assert!(
            !listed(&list_buyer_conversations(&store, 1, STORE))[0].backed_up,
            "exporting a conversation reported it as saved"
        );
    }

    /// **Marking clears the warning on THAT conversation and no other.**
    ///
    /// The granularity is the point: one saved string covers one
    /// conversation, so marking a set would let it clear a warning about a
    /// conversation it does not contain.
    #[test]
    fn marking_a_conversation_clears_its_warning_and_no_others() {
        let mut store = MemSecrets::default();
        let (tag, record) = conversation(10);
        let (other_tag, other) = conversation(11);
        store_buyer_conversation(&mut store, 1, STORE, &record);
        store_buyer_conversation(&mut store, 2, STORE, &other);

        assert!(
            marked(&mark_conversation_backed_up(&mut store, 3, STORE, &tag))
                .as_ref()
                .expect("must mark")
        );

        for recalled in listed(&list_buyer_conversations(&store, 1, STORE)) {
            if recalled.buyer_public_key == tag {
                assert!(recalled.backed_up, "the marked conversation is not marked");
            } else {
                assert_eq!(recalled.buyer_public_key, other_tag);
                assert!(
                    !recalled.backed_up,
                    "marking one conversation cleared the warning on another, which is the \
                     granularity form of silencing a warning about a key nobody has a backup of"
                );
            }
        }
    }

    /// Marking must not resurrect a conversation, or bring one into being.
    #[test]
    fn marking_a_conversation_that_is_not_here_stores_nothing() {
        let mut store = MemSecrets::default();
        assert!(!marked(&mark_conversation_backed_up(
            &mut store, 1, STORE, &[7u8; 32]
        ))
        .as_ref()
        .expect("not an error"));
        assert!(store.is_empty(), "marking created a conversation");
    }

    /// **A refused write means the buyer is NOT told their backup was
    /// recorded.**
    ///
    /// The warning staying on is the safe direction, but reporting success
    /// while the record was not written would leave the buyer believing a
    /// warning had been cleared when it had not.
    #[test]
    fn marking_reports_a_failure_when_the_node_refuses_the_write() {
        let mut store = MemSecrets::default();
        let (tag, record) = conversation(43);
        store_buyer_conversation(&mut store, 1, STORE, &record);
        store.writes_fail = true;

        let response = mark_conversation_backed_up(&mut store, 2, STORE, &tag);
        let message = marked(&response)
            .as_ref()
            .expect_err("a refused write must be reported");
        assert!(message.contains("refused"), "{message}");
        assert!(
            !listed(&list_buyer_conversations(&store, 3, STORE))[0].backed_up,
            "the warning was cleared by a write that did not happen"
        );
    }

    /// **Forgetting a conversation leaves no backup marker behind.**
    ///
    /// The reason the marker is a field of the record rather than a key of
    /// its own, as the ghostkey vault has it: a marker keyed by store and tag
    /// would outlive the record it describes, which is exactly the durable
    /// local note that `forget_buyer_conversation` exists to remove.
    #[test]
    fn forgetting_a_conversation_leaves_no_backup_marker_behind() {
        let mut store = MemSecrets::default();
        let (tag, record) = conversation(12);
        store_buyer_conversation(&mut store, 1, STORE, &record);
        mark_conversation_backed_up(&mut store, 2, STORE, &tag);

        forget_buyer_conversation(&mut store, 3, STORE, &tag);
        assert!(
            store.is_empty(),
            "forgetting left something behind: {:?}",
            store
                .list_secrets(b"")
                .iter()
                .map(|k| String::from_utf8_lossy(k).into_owned())
                .collect::<Vec<_>>()
        );
    }

    /// Exporting a conversation this node does not hold is refused rather
    /// than answered as an empty string that looks like a saved backup.
    #[test]
    fn exporting_a_conversation_this_node_does_not_hold_is_refused() {
        let store = MemSecrets::default();
        let response = export_buyer_conversation(&store, 1, STORE, &[5u8; 32]);
        let message = exported(&response)
            .as_ref()
            .expect_err("an empty backup must be refused");
        assert!(message.contains("does not hold"), "{message}");
    }

    /// **A backup is a capability, and the test says so.**
    ///
    /// It contains the secret itself -- that is what makes it work on another
    /// machine, and what makes it worth as much as the conversation it
    /// restores. Pinned so that a future "safer" export that omitted it fails
    /// here rather than in a buyer's hands.
    #[test]
    fn a_backup_contains_the_secret_itself() {
        let mut store = MemSecrets::default();
        let (tag, record) = conversation(13);
        store_buyer_conversation(&mut store, 1, STORE, &record);

        let decoded = decode_backup(&export(&store, STORE, &tag)).expect("decode");
        assert_eq!(decoded.conversation.secret, record.secret);
    }

    /// **A backup string longer than the cap is refused before it is
    /// decoded.**
    ///
    /// Base58 decoding is quadratic in the input length, so an unbounded
    /// paste is an unbounded amount of the node's CPU. Found by measurement:
    /// a 253-conversation round trip took 72 seconds in a debug build.
    #[test]
    fn a_backup_string_longer_than_the_cap_is_refused_without_decoding_it() {
        let mut store = MemSecrets::default();
        let huge = format!(
            "{BUYER_CONVERSATION_BACKUP_PREFIX}{}",
            "1".repeat(MAX_BACKUP_STRING_BYTES + 1)
        );
        let before = std::time::Instant::now();
        let response = import_buyer_conversation(&mut store, 1, &huge);
        let message = imported(&response)
            .as_ref()
            .expect_err("an oversized paste must be refused");
        assert!(message.contains("never more than"), "{message}");
        assert!(
            before.elapsed() < std::time::Duration::from_secs(1),
            "the refusal took long enough that the string was probably decoded first"
        );
    }

    /// An honest backup is comfortably inside the cap, so the bound never
    /// refuses a real one.
    #[test]
    fn an_honest_backup_is_far_inside_the_length_cap() {
        let mut store = MemSecrets::default();
        let (tag, record) = conversation(14);
        store_buyer_conversation(&mut store, 1, STORE, &record);
        let backup = export(&store, STORE, &tag);
        assert!(
            backup.len() * 4 < MAX_BACKUP_STRING_BYTES,
            "an honest backup is {} bytes against a cap of {MAX_BACKUP_STRING_BYTES}, which \
             leaves too little room to be sure the cap never refuses a real one",
            backup.len()
        );
        // The band pins the FIGURE, not just the margin. `MAX_BACKUP_STRING_BYTES`
        // documents a size, and an undocumented drift in the format would
        // silently make that sentence wrong -- which is how it came to say
        // 210 when the real number was nearly twice that.
        assert!(
            (300..500).contains(&backup.len()),
            "an honest backup is now {} characters; the size documented on \
             `MAX_BACKUP_STRING_BYTES` says just under 400, so update one or the other",
            backup.len()
        );
    }

    /// **A record whose keys cannot be derived is refused, and does not
    /// occupy a slot.**
    ///
    /// Without this the record stores, `recall` silently drops it (it can
    /// derive nothing), and the buyer has a cap slot permanently consumed by
    /// something invisible in the list and absent from the refusals.
    #[test]
    fn a_record_whose_keys_cannot_be_derived_is_refused_and_stores_nothing() {
        let mut store = MemSecrets::default();
        let (tag, record) = conversation(42);
        let paste = encode_backup(&BuyerConversationBackupV2 {
            store_contract_id: [3u8; 32],
            conversation: BuyerConversationRecord {
                // The all-zero point: a low-order key, so the shared secret is
                // all zeros and the "conversation key" would be a constant
                // anyone can compute.
                seller_public_key: [0u8; 32],
                ..record
            },
        })
        .expect("encode");

        match imported(&import_buyer_conversation(&mut store, 1, &paste))
            .as_ref()
            .expect("not an error")
        {
            ImportedConversation::Refused {
                buyer_public_key, ..
            } => assert_eq!(buyer_public_key, &tag),
            other => panic!("expected Refused, got {other:?}"),
        }
        assert!(
            store.is_empty(),
            "a record that recalls nothing is occupying a slot"
        );
    }

    /// **A conversation that exists only on this node is the LAST thing
    /// evicted, not the first.**
    ///
    /// The reproduction is the reviewer's: the buyer holds genuine
    /// conversations, is handed backup strings by somebody else, and pastes
    /// them. Import refuses at the cap but fills the store right up to it,
    /// and the next conversation the buyer opens triggers an eviction. Ranked
    /// by age alone the victim is one of the buyer's own -- destroyed
    /// silently, while records the attacker supplied survive.
    #[test]
    fn a_conversation_that_exists_only_here_outlives_an_imported_one() {
        let mut store = MemSecrets::default();

        // The buyer's own, oldest of all and backed up nowhere.
        let mut mine = Vec::new();
        for seed in 0..3u32 {
            let (tag, record) = conversation(seed);
            store_buyer_conversation(&mut store, seed as u64, STORE, &record);
            mine.push(tag);
        }

        // Backups somebody else supplied, dated as far in the future as the
        // field allows -- nothing signs `created_at`. Two by the real import
        // path, the rest stored directly in the shape import produces, so the
        // test fills the cap without paying for hundreds of base58 decodes.
        for seed in 100..102u32 {
            let (_, record) = conversation(seed);
            let paste = encode_backup(&BuyerConversationBackupV2 {
                store_contract_id: [3u8; 32],
                conversation: BuyerConversationRecord {
                    created_at: i64::MAX,
                    ..record
                },
            })
            .expect("encode");
            assert!(matches!(
                imported(&import_buyer_conversation(&mut store, seed as u64, &paste))
                    .as_ref()
                    .expect("import"),
                ImportedConversation::Imported { .. }
            ));
        }
        for seed in 1_000..(1_000 + MAX_BUYER_CONVERSATIONS as u32 - 5) {
            let (_, record) = conversation(seed);
            store_buyer_conversation(
                &mut store,
                seed as u64,
                STORE,
                &BuyerConversationRecord {
                    created_at: i64::MAX,
                    backed_up: true,
                    imported: true,
                    ..record
                },
            );
        }
        assert_eq!(
            listed(&list_buyer_conversations(&store, 1, STORE)).len(),
            MAX_BUYER_CONVERSATIONS,
            "precondition: the store is full"
        );

        // One more conversation of the buyer's own forces an eviction.
        let (fresh, record) = conversation(500);
        stored(&store_buyer_conversation(&mut store, 1000, STORE, &record))
            .as_ref()
            .expect("must store");

        let kept: Vec<[u8; 32]> = listed(&list_buyer_conversations(&store, 1, STORE))
            .into_iter()
            .map(|c| c.buyer_public_key)
            .collect();
        for tag in &mine {
            assert!(
                kept.contains(tag),
                "a conversation that exists only on this node was destroyed to make room for \
                 one the buyer could restore from the string they were given"
            );
        }
        assert!(kept.contains(&fresh));
        assert_eq!(kept.len(), MAX_BUYER_CONVERSATIONS);
    }

    /// **An imported conversation goes before one opened here, even when both
    /// are backed up.**
    ///
    /// This is the half `backed_up` alone does not cover. Once the buyer has
    /// saved their own conversations too, both sit in the same tier and the
    /// order falls to `created_at` -- which arrives inside the backup string
    /// and is free for the other side to choose. `imported` is set by the
    /// delegate from which call arrived, so it cannot be claimed.
    #[test]
    fn an_imported_conversation_is_evicted_before_one_opened_here() {
        let mut store = MemSecrets::default();

        // The buyer's own, saved, and OLDER than everything else -- so age
        // alone would evict it first.
        let (mine, record) = conversation(1);
        store_buyer_conversation(
            &mut store,
            1,
            STORE,
            &BuyerConversationRecord {
                created_at: 1,
                backed_up: true,
                ..record
            },
        );
        for seed in 200..(200 + MAX_BUYER_CONVERSATIONS as u32 - 1) {
            let (_, record) = conversation(seed);
            store_buyer_conversation(
                &mut store,
                seed as u64,
                STORE,
                &BuyerConversationRecord {
                    created_at: i64::MAX,
                    backed_up: true,
                    imported: true,
                    ..record
                },
            );
        }

        let (fresh, record) = conversation(700);
        stored(&store_buyer_conversation(&mut store, 999, STORE, &record))
            .as_ref()
            .expect("must store");

        let kept: Vec<[u8; 32]> = listed(&list_buyer_conversations(&store, 1, STORE))
            .into_iter()
            .map(|c| c.buyer_public_key)
            .collect();
        assert!(
            kept.contains(&mine),
            "the oldest conversation was evicted, which is what happens when the ranking \
             believes a timestamp the other side supplied"
        );
        assert!(kept.contains(&fresh));
    }

    /// **An eviction is reported, so the buyer can be told a conversation is
    /// gone.**
    ///
    /// The design doc's own framing of the expensive direction is "the
    /// confession becomes unreadable and the buyer has no recourse, with no
    /// error at any layer". A response that cannot express "something was
    /// discarded" is that no-error-at-any-layer.
    #[test]
    fn an_eviction_is_reported() {
        let mut store = MemSecrets::default();
        let mut oldest = [0u8; 32];
        for seed in 0..(MAX_BUYER_CONVERSATIONS as u32) {
            let (tag, record) = conversation(seed);
            if seed == 0 {
                oldest = tag;
            }
            store_buyer_conversation(&mut store, seed as u64, STORE, &record);
        }

        let (_, record) = conversation(900);
        let response = store_buyer_conversation(&mut store, 1, STORE, &record);
        match &response {
            HarvestDelegateResponse::BuyerConversationStored { evicted, .. } => {
                assert_eq!(
                    evicted.len(),
                    1,
                    "a conversation was discarded and the answer did not say so"
                );
                assert_eq!(evicted[0].buyer_public_key, oldest);
                assert!(
                    !evicted[0].was_backed_up,
                    "this one existed only here, and the buyer needs to be told that \
                     specifically"
                );
            }
            other => panic!("expected BuyerConversationStored, got {other:?}"),
        }
        stored(&response).as_ref().expect("must still store");
    }

    /// Nothing evicted, nothing reported -- so a report is evidence rather
    /// than noise on every message sent.
    #[test]
    fn storing_without_evicting_reports_no_eviction() {
        let mut store = MemSecrets::default();
        let (_, record) = conversation(7);
        match store_buyer_conversation(&mut store, 1, STORE, &record) {
            HarvestDelegateResponse::BuyerConversationStored { evicted, .. } => {
                assert!(evicted.is_empty())
            }
            other => panic!("expected BuyerConversationStored, got {other:?}"),
        }
    }
}
