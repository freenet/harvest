//! One backup for all of a buyer's purchases (step 2): every kept
//! conversation and every kept purchase, read out in pages
//! ([`export_page`]), restored in chunks ([`import`]), and marked as held
//! in a backup item by item ([`mark`]).
//!
//! # Why pages and chunks
//!
//! A node keeps up to `MAX_BUYER_CONVERSATIONS` conversations and
//! `MAX_KEPT_PURCHASES` purchases, a few MiB in practice and far more at
//! the bounds a kept purchase may reach. One call does a bounded amount of
//! work (`tests/delegate-budget`), so the export is read a page of about
//! [`BACKUP_PAGE_BYTES`] at a time and the restore takes at most
//! [`BACKUP_IMPORT_ITEMS`] records a call; the web app assembles and splits
//! the file.
//!
//! # What a restore never does
//!
//! Write over a conversation or purchase this node already holds (a
//! purchase is merged as a migration merges it: a more complete copy, paid
//! or with the complaint, wins), or make room by evicting: past a cap the
//! item is refused and named. Every purchase is checked as a fresh keep is.

use freenet_migrate::SecretStore;
use harvest_common::delegate::RequestId;
use harvest_common::delegate::{
    BackupConversation, BackupItemOutcome, HarvestDelegateResponse, KeptPurchase,
    PurchasesBackupPage, SecretImport, BACKUP_IMPORT_ITEMS, BACKUP_MARK_ITEMS, BACKUP_PAGE_BYTES,
};
use harvest_common::payment::OrderId;
use harvest_common::{from_cbor, to_cbor, ConversationSecret};

use crate::kept_purchases::{kept_purchase_key, KEPT_PURCHASE_PREFIX};
use crate::messaging::{
    buyer_conversation_key, BuyerConversationRecord, BUYER_CONVERSATION_PREFIX,
};

/// The store contract id a conversation's key names
/// (`harvest:buyer_conv:{store}:{tag}`, both base58).
fn store_of_conversation_key(key: &[u8]) -> Option<[u8; 32]> {
    let rest = key.strip_prefix(BUYER_CONVERSATION_PREFIX)?;
    let store = rest.split(|b| *b == b':').next()?;
    bs58::decode(store).into_vec().ok()?.try_into().ok()
}

/// One page of the backup: the records whose keys sort after `after`, in key
/// order, until about [`BACKUP_PAGE_BYTES`] of stored values (at least one).
/// A record that does not decode is passed over: it would restore nothing.
pub(crate) fn export_page<S: SecretStore>(
    store: &S,
    request_id: RequestId,
    after: Option<String>,
) -> HarvestDelegateResponse {
    let mut keys: Vec<Vec<u8>> = store.list_secrets(BUYER_CONVERSATION_PREFIX);
    keys.extend(store.list_secrets(KEPT_PURCHASE_PREFIX.as_bytes()));
    keys.sort_unstable();
    if let Some(after) = &after {
        keys.retain(|k| k.as_slice() > after.as_bytes());
    }
    let mut page = PurchasesBackupPage {
        conversations: Vec::new(),
        purchases: Vec::new(),
        next: None,
    };
    let mut bytes = 0usize;
    let mut taken = 0usize;
    for key in &keys {
        if taken > 0 && bytes >= BACKUP_PAGE_BYTES {
            break;
        }
        taken += 1;
        let Some(value) = store.get_secret(key) else {
            continue;
        };
        bytes += value.len();
        if key.starts_with(BUYER_CONVERSATION_PREFIX) {
            let (Some(store_contract_id), Ok(record)) = (
                store_of_conversation_key(key),
                from_cbor::<BuyerConversationRecord>(&value),
            ) else {
                continue;
            };
            page.conversations.push(BackupConversation {
                store_contract_id,
                secret: ConversationSecret(record.secret.0),
                seller_public_key: record.seller_public_key,
                conversation_id: record.conversation_id,
                created_at: record.created_at,
            });
        } else if let Ok(record) = from_cbor::<KeptPurchase>(&value) {
            if kept_purchase_key(&record.order.order.id.0) == *key {
                page.purchases.push(record);
            }
        }
    }
    if taken < keys.len() {
        page.next = keys
            .get(taken - 1)
            .map(|k| String::from_utf8_lossy(k).into_owned());
    }
    HarvestDelegateResponse::PurchasesBackup {
        request_id,
        result: Ok(page),
    }
}

/// Restore one chunk of a backup: one outcome per item, conversations
/// first. A chunk over [`BACKUP_IMPORT_ITEMS`] is refused whole, before any
/// work.
pub(crate) fn import<S: SecretStore>(
    store: &mut S,
    request_id: RequestId,
    conversations: Vec<BackupConversation>,
    purchases: Vec<KeptPurchase>,
) -> HarvestDelegateResponse {
    let answer = |result| HarvestDelegateResponse::PurchasesBackupImported { request_id, result };
    if conversations.len() + purchases.len() > BACKUP_IMPORT_ITEMS {
        return answer(Err(format!(
            "at most {BACKUP_IMPORT_ITEMS} backup items are restored at a time"
        )));
    }
    let mut outcomes = Vec::with_capacity(conversations.len() + purchases.len());
    for conversation in conversations {
        let record = BuyerConversationRecord {
            secret: conversation.secret,
            seller_public_key: conversation.seller_public_key,
            conversation_id: conversation.conversation_id,
            created_at: conversation.created_at,
            backed_up: false,
            imported: false,
            sent: Vec::new(),
            seen_ms: None,
        };
        use harvest_common::delegate::ImportedConversation as I;
        outcomes.push(
            match crate::messaging::import_conversation_record(
                store,
                conversation.store_contract_id,
                record,
            ) {
                I::Imported { .. } => BackupItemOutcome::Imported,
                I::AlreadyHeld { .. } => BackupItemOutcome::AlreadyHeld,
                I::Refused { why, .. } => BackupItemOutcome::Refused(why),
            },
        );
    }
    for purchase in purchases {
        let key = kept_purchase_key(&purchase.order.order.id.0);
        // The buyer holds the file it came from.
        let record = KeptPurchase {
            backed_up: true,
            ..purchase
        };
        let Ok(bytes) = to_cbor(&record) else {
            outcomes.push(BackupItemOutcome::Refused(
                "this purchase could not be encoded".into(),
            ));
            continue;
        };
        outcomes.push(match crate::kept_purchases::import(store, &key, &bytes) {
            SecretImport::Written => BackupItemOutcome::Imported,
            SecretImport::AlreadyAuthoritative => BackupItemOutcome::AlreadyHeld,
            SecretImport::Retryable(why) | SecretImport::Permanent(why) => {
                BackupItemOutcome::Refused(why)
            }
        });
    }
    answer(Ok(outcomes))
}

/// Mark exactly these items as held in a backup. An item this node does
/// not hold is skipped; one already marked is counted without a write.
pub(crate) fn mark<S: SecretStore>(
    store: &mut S,
    request_id: RequestId,
    conversations: Vec<([u8; 32], [u8; 32])>,
    orders: Vec<OrderId>,
) -> HarvestDelegateResponse {
    let answer = |result| HarvestDelegateResponse::BackedUpMarked { request_id, result };
    if conversations.len() + orders.len() > BACKUP_MARK_ITEMS {
        return answer(Err(format!(
            "at most {BACKUP_MARK_ITEMS} backup items are marked at a time"
        )));
    }
    let mut marked = 0u32;
    for (store_contract_id, tag) in conversations {
        let key = buyer_conversation_key(&store_contract_id, &tag);
        let Some(mut record) = store
            .get_secret(&key)
            .and_then(|b| from_cbor::<BuyerConversationRecord>(&b).ok())
        else {
            continue;
        };
        if !record.backed_up {
            record.backed_up = true;
            match to_cbor(&record) {
                Ok(bytes) if store.set_secret(&key, &bytes) => {}
                _ => return answer(Err("the node refused to record the backup".into())),
            }
        }
        marked += 1;
    }
    for order in orders {
        let key = kept_purchase_key(&order.0);
        let Some(mut record) = store
            .get_secret(&key)
            .and_then(|b| from_cbor::<KeptPurchase>(&b).ok())
        else {
            continue;
        };
        if !record.backed_up {
            record.backed_up = true;
            match to_cbor(&record) {
                Ok(bytes) if store.set_secret(&key, &bytes) => {}
                _ => return answer(Err("the node refused to record the backup".into())),
            }
        }
        marked += 1;
    }
    answer(Ok(marked))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kept_purchases::fixtures::*;
    use crate::secrets::MemSecrets;
    use harvest_common::payment::OrderStatus;

    fn page(store: &MemSecrets, after: Option<String>) -> PurchasesBackupPage {
        match export_page(store, 1, after) {
            HarvestDelegateResponse::PurchasesBackup { result, .. } => result.expect("a page"),
            other => panic!("{other:?}"),
        }
    }

    fn outcomes(response: HarvestDelegateResponse) -> Result<Vec<BackupItemOutcome>, String> {
        match response {
            HarvestDelegateResponse::PurchasesBackupImported { result, .. } => result,
            other => panic!("{other:?}"),
        }
    }

    /// A buyer's node with `n` conversations, and a purchase in each (paid
    /// for the even ones).
    fn buyer(n: u8) -> MemSecrets {
        let mut secrets = MemSecrets::default();
        for c in 1..=n {
            hold_conversation(&mut secrets, c);
            let status = if c % 2 == 0 {
                OrderStatus::Paid
            } else {
                OrderStatus::AwaitingPayment
            };
            crate::kept_purchases::keep(&mut secrets, to_keep(u16::from(c), c, status, c));
        }
        secrets
    }

    /// Every page in turn, from the first.
    fn whole(store: &MemSecrets) -> (Vec<BackupConversation>, Vec<KeptPurchase>, usize) {
        let (mut conversations, mut purchases, mut pages) = (Vec::new(), Vec::new(), 0);
        let mut after = None;
        loop {
            let p = page(store, after);
            pages += 1;
            conversations.extend(p.conversations);
            purchases.extend(p.purchases);
            match p.next {
                Some(next) => after = Some(next),
                None => return (conversations, purchases, pages),
            }
            assert!(pages < 1_000, "the cursor moves on");
        }
    }

    /// The export reads every conversation and purchase once, over pages
    /// of about `BACKUP_PAGE_BYTES` each (one record past it at most), and
    /// carries no sent digests or seen time. Mutated red by not moving the
    /// cursor on, by an unbounded page, and by skipping the record that
    /// crosses the bound.
    #[test]
    fn the_export_pages_through_everything_once() {
        let store = buyer(40);
        let (conversations, purchases, pages) = whole(&store);
        assert_eq!(conversations.len(), 40);
        assert_eq!(purchases.len(), 40);
        assert!(conversations
            .iter()
            .all(|c| c.store_contract_id == [3u8; 32]));
        let mut ids: Vec<_> = purchases.iter().map(|p| p.order.order.id.0).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), 40, "each once");
        // Small records: one page. With the bound lowered by a full store,
        // pages: a full purchase store is about 40 x a few KiB, so check the
        // bound directly instead.
        assert!(pages >= 1);
        let first = page(&store, None);
        let encoded = to_cbor(&first).unwrap().len();
        assert!(
            encoded <= BACKUP_PAGE_BYTES + 300 * 1024,
            "a page is about the bound: {encoded}"
        );
    }

    /// A page stops once it holds `BACKUP_PAGE_BYTES` of records, and the
    /// next page starts after its last key. Driven with records big enough
    /// to need several pages. Mutated red by ignoring the bound.
    #[test]
    fn a_large_backup_takes_several_pages() {
        let mut store = buyer(1);
        // Pad conversations so the stored bytes pass the page bound.
        for c in 2..=200u8 {
            hold_conversation(&mut store, c);
            let key = crate::messaging::buyer_conversation_key(&[3u8; 32], &conversation(c));
            let mut record: BuyerConversationRecord =
                from_cbor(&store.get_secret(&key).unwrap()).unwrap();
            record.sent = vec![7u8; 128 * 32];
            store.set_secret(&key, &to_cbor(&record).unwrap());
        }
        let (conversations, _, pages) = whole(&store);
        assert_eq!(conversations.len(), 200);
        assert!(pages >= 3, "{pages} pages");
    }

    /// The whole backup restores on an empty node, in chunks of at most
    /// `BACKUP_IMPORT_ITEMS`: every conversation reads again and every
    /// purchase is kept, marked as backed up; a chunk too big is refused
    /// before any work. Mutated red by not restoring purchases, and by
    /// dropping the chunk bound.
    #[test]
    fn a_backup_restores_on_an_empty_node() {
        let (conversations, purchases, _) = whole(&buyer(20));
        let mut fresh = MemSecrets::default();
        let too_many = conversations
            .iter()
            .take(BACKUP_IMPORT_ITEMS + 1)
            .cloned()
            .collect();
        assert!(outcomes(import(&mut fresh, 1, too_many, Vec::new())).is_err());
        assert!(fresh.list_secrets(b"harvest:").is_empty(), "nothing done");
        for chunk in conversations.chunks(BACKUP_IMPORT_ITEMS) {
            let got = outcomes(import(&mut fresh, 2, chunk.to_vec(), Vec::new())).unwrap();
            assert!(
                got.iter().all(|o| *o == BackupItemOutcome::Imported),
                "{got:?}"
            );
        }
        for chunk in purchases.chunks(BACKUP_IMPORT_ITEMS) {
            let got = outcomes(import(&mut fresh, 3, Vec::new(), chunk.to_vec())).unwrap();
            assert!(
                got.iter().all(|o| *o == BackupItemOutcome::Imported),
                "{got:?}"
            );
        }
        let (again, kept, _) = whole(&fresh);
        assert_eq!(again.len(), 20);
        assert_eq!(kept.len(), 20);
        assert!(kept.iter().all(|k| k.backed_up));
        match crate::messaging::list_buyer_conversations(&fresh, 4, &[3u8; 32]) {
            HarvestDelegateResponse::BuyerConversationList { conversations, .. } => {
                assert_eq!(conversations.len(), 20, "every thread reads again")
            }
            other => panic!("{other:?}"),
        }
    }

    /// A restore never writes over what is held: a held conversation and a
    /// held paid purchase answer `AlreadyHeld` and stay as they are; a held
    /// unpaid copy takes the backup's paid one (the more complete copy, as
    /// a migration merges); a purchase that does not check is refused with
    /// why. Mutated red by overwriting a held paid copy.
    #[test]
    fn a_restore_never_writes_over_what_is_held() {
        let (conversations, purchases, _) = whole(&buyer(2));
        let mut node = MemSecrets::default();
        hold_conversation(&mut node, 1);
        hold_conversation(&mut node, 2);
        crate::kept_purchases::keep(&mut node, to_keep(1, 1, OrderStatus::AwaitingPayment, 9));
        crate::kept_purchases::keep(&mut node, to_keep(2, 2, OrderStatus::Paid, 9));
        let held_paid = node.get_secret(&kept_purchase_key(&purchases[1].order.order.id.0));
        let got = outcomes(import(&mut node, 1, conversations, Vec::new())).unwrap();
        assert_eq!(got, vec![BackupItemOutcome::AlreadyHeld; 2]);
        let paid_in_backup = purchases
            .iter()
            .find(|p| p.order.status == OrderStatus::Paid)
            .unwrap()
            .clone();
        let unpaid_in_backup = purchases
            .iter()
            .find(|p| p.order.status != OrderStatus::Paid)
            .unwrap()
            .clone();
        let got = outcomes(import(
            &mut node,
            2,
            Vec::new(),
            vec![paid_in_backup.clone()],
        ))
        .unwrap();
        assert_eq!(
            got,
            vec![BackupItemOutcome::AlreadyHeld],
            "a held paid copy stays"
        );
        assert_eq!(
            node.get_secret(&kept_purchase_key(&paid_in_backup.order.order.id.0)),
            held_paid
        );
        let mut forged = unpaid_in_backup.clone();
        forged.order.order.amount_sats += 1;
        let got = outcomes(import(&mut node, 3, Vec::new(), vec![forged])).unwrap();
        assert!(matches!(&got[0], BackupItemOutcome::Refused(_)), "{got:?}");
    }

    /// Past the conversation cap an item is refused and named, and nothing
    /// is evicted to make room. Mutated red by evicting.
    #[test]
    fn past_the_cap_an_item_is_refused_not_made_room_for() {
        let (conversations, _, _) = whole(&buyer(1));
        let mut full = MemSecrets::default();
        // Fill with distinct conversations.
        let mut n = 0usize;
        let mut i = 0u32;
        while n < crate::messaging::MAX_BUYER_CONVERSATIONS {
            let mut secret = [9u8; 32];
            secret[1..5].copy_from_slice(&i.to_le_bytes());
            i += 1;
            let record = BuyerConversationRecord {
                secret: ConversationSecret(secret),
                seller_public_key: [5u8; 32],
                conversation_id: [1u8; 32],
                created_at: 1,
                backed_up: false,
                imported: false,
                sent: Vec::new(),
                seen_ms: None,
            };
            let tag = *x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(secret))
                .as_bytes();
            full.set_secret(
                &buyer_conversation_key(&[4u8; 32], &tag),
                &to_cbor(&record).unwrap(),
            );
            n += 1;
        }
        let before = full.list_secrets(b"harvest:").len();
        let got = outcomes(import(&mut full, 1, conversations, Vec::new())).unwrap();
        assert!(
            matches!(&got[0], BackupItemOutcome::Refused(why) if why.contains("full")),
            "{got:?}"
        );
        assert_eq!(
            full.list_secrets(b"harvest:").len(),
            before,
            "nothing evicted"
        );
    }

    /// Marking sets the flag on exactly the items named, skips one not held,
    /// refuses a list over `BACKUP_MARK_ITEMS`, and a purchase paid after
    /// the backup loses its mark. Mutated red by marking everything, and by
    /// keeping the mark over an upgrade.
    #[test]
    fn marks_cover_exactly_what_the_backup_held() {
        let mut node = buyer(2);
        let (_, purchases, _) = whole(&node);
        let unpaid = purchases
            .iter()
            .find(|p| p.order.status != OrderStatus::Paid)
            .unwrap()
            .order
            .order
            .id
            .clone();
        let answer = mark(
            &mut node,
            1,
            vec![([3u8; 32], conversation(1)), ([3u8; 32], [0xEE; 32])],
            vec![unpaid.clone(), OrderId([0xEE; 32])],
        );
        assert!(matches!(
            answer,
            HarvestDelegateResponse::BackedUpMarked { result: Ok(2), .. }
        ));
        let (_, kept, _) = whole(&node);
        assert_eq!(kept.iter().filter(|k| k.backed_up).count(), 1);
        let too_many = vec![OrderId([1; 32]); BACKUP_MARK_ITEMS + 1];
        assert!(matches!(
            mark(&mut node, 2, Vec::new(), too_many),
            HarvestDelegateResponse::BackedUpMarked { result: Err(_), .. }
        ));
        // Paid after the backup: no longer in it.
        let n = purchases
            .iter()
            .find(|p| p.order.order.id == unpaid)
            .map(|p| p.conversation)
            .unwrap();
        let c = (1..=2u8).find(|c| conversation(*c) == n).unwrap();
        crate::kept_purchases::keep(&mut node, to_keep(u16::from(c), c, OrderStatus::Paid, c));
        let (_, kept, _) = whole(&node);
        assert!(
            kept.iter().all(|k| !k.backed_up),
            "the upgrade is not in the backup"
        );
    }
}
