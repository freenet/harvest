//! Asking a bridge to watch an order's payment address (#59).
//!
//! A bridge scans only the scripts it has been asked to watch, and it takes
//! those requests through its request inbox: a contract to which a sender
//! appends an entry signed by a Ghost Key and sealed so that only the bridge
//! can read it. Until an order's address is on that list, a payment to it is
//! never seen and the order never reaches `Paid`.
//!
//! This module builds the entries and does no I/O, so what it builds is tested
//! against the real inbox contract and the real bridge key rather than against
//! a stand-in for either.
//!
//! # Dating an entry
//!
//! Every entry carries a Bitcoin mainnet height, and the inbox admits one only
//! within `WINDOW_BLOCKS` above the floor the bridge last signed. A sender
//! dates against that floor, with [`sender_height`], and NOT against the chain
//! tip: the floor trails the tip, so a tip-dated entry lands above the window
//! and the contract drops it without any error. Harvest#59 as first written
//! said to date by the tip. That predates the inbox, and followed literally it
//! would have sent every request somewhere nothing reads.
//!
//! # Locating the inbox
//!
//! Nothing here names the inbox's code hash. It comes from the bridge's
//! generation pointer at runtime, because a hash written into this build goes
//! stale on the bridge's next deploy and then names a contract the bridge no
//! longer reads. That is exactly what happened to the address contract's
//! (#30).

use freenet_bitcoin_common::{to_cbor, BitcoinNetwork, BridgeId};
use freenet_bitcoin_inbox::{
    sender_height, Action, ByteBuf, EntryKey, GhostkeyId, InboxDelta, InboxEntryBody,
    InboxParameters, InboxRequest, InboxStateV1, SignedFloor, WireEntry, MAX_SCRIPTS_PER_REQUEST,
};
use freenet_stdlib::prelude::{CodeHash, ContractKey, Parameters};

/// `bridge`'s production inbox parameters, encoded as the bridge encodes them.
///
/// Deliberately the bridge's own encoder and not Harvest's: the contract id is
/// a hash over these bytes, so two encoders that merely agree on the value
/// would still address two different contracts if their bytes ever differed.
pub fn inbox_params_bytes(bridge: BridgeId) -> Result<Vec<u8>, String> {
    to_cbor(&InboxParameters::production(bridge))
}

/// The key of `bridge`'s inbox, given the inbox code hash its generation
/// pointer names.
pub fn inbox_contract_key(bridge: BridgeId, code_hash: CodeHash) -> Result<ContractKey, String> {
    let params = Parameters::from(inbox_params_bytes(bridge)?);
    Ok(ContractKey::from_id_and_code(
        crate::migrate::current_id(&code_hash, &params),
        code_hash,
    ))
}

/// The timestamp for a sender's next request.
///
/// A bridge applies one sender's requests about a script in the order they
/// were made, and ignores one that is not strictly later than the last, a
/// renewal included. So this is the clock, unless the clock has not yet moved
/// past the last request sent, in which case it is one millisecond after it.
pub fn next_made_at_ms(now_ms: u64, last_sent_ms: Option<u64>) -> u64 {
    match last_sent_ms {
        Some(last) if last >= now_ms => last + 1,
        _ => now_ms,
    }
}

/// Watch requests for `scripts` on `network`.
///
/// A script named twice is asked for once. The scripts are split so no request
/// names more than the inbox allows, and each request is dated one millisecond
/// after the one before it, starting at `made_at_ms`, so they stay strictly
/// ordered for the bridge.
pub fn watch_requests(
    network: BitcoinNetwork,
    scripts: &[Vec<u8>],
    made_at_ms: u64,
    scan_from_height: Option<u32>,
) -> Vec<InboxRequest> {
    let mut unique: Vec<&Vec<u8>> = Vec::new();
    for s in scripts {
        if !unique.contains(&s) {
            unique.push(s);
        }
    }
    unique
        .chunks(MAX_SCRIPTS_PER_REQUEST)
        .enumerate()
        .map(|(i, batch)| InboxRequest {
            action: Action::Watch,
            network,
            scripts: batch.iter().map(|s| ByteBuf((*s).clone())).collect(),
            scan_from_height,
            made_at_ms: made_at_ms + i as u64,
        })
        .collect()
}

/// An entry laid out for the Ghost Key to sign.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedEntry {
    /// The mainnet height the entry is dated at.
    pub mainnet_height: u32,
    /// The exact bytes to ask the ghostkey delegate to sign.
    pub signing_payload: Vec<u8>,
}

/// Seal `request` to `bridge` and lay out the entry that carries it, dated
/// against the inbox's current `floor`.
///
/// The seal is bound both to the Ghost Key that will sign the entry and to the
/// height it is dated at, so both are fixed here, before anything is signed:
/// an entry signed by another key or re-dated afterwards does not open.
pub fn prepare_entry(
    bridge: BridgeId,
    ghostkey: GhostkeyId,
    floor: &SignedFloor,
    request: &InboxRequest,
) -> Result<PreparedEntry, String> {
    let mainnet_height = sender_height(floor.height);
    let sealed = freenet_bitcoin_inbox::seal::seal(&bridge, &ghostkey, mainnet_height, request)?;
    let body = InboxEntryBody {
        bridge,
        mainnet_height,
        sealed,
    };
    Ok(PreparedEntry {
        mainnet_height,
        signing_payload: body.signing_payload()?,
    })
}

/// The contract update that appends a signed entry to the inbox.
///
/// It carries the floor the entry was dated against, since the inbox admits an
/// entry only alongside a floor it can check the date against.
pub fn submission_bytes(floor: &SignedFloor, entry: WireEntry) -> Result<Vec<u8>, String> {
    to_cbor(&InboxDelta::submission(Some(floor.clone()), entry))
}

/// How long after a watch request is sent before it is renewed. A bridge lets
/// a watch lapse about a day after the request that last asked for it, so this
/// renews with half a day to spare.
pub const RENEW_AFTER_MS: u64 = 12 * 60 * 60 * 1000;

/// How long a just-sent request is given to land in the inbox before its
/// absence is read as its having been dropped.
pub const LAND_GRACE_MS: u64 = 2 * 60 * 1000;

/// What this tab has sent the bridge about one script, and what it has seen
/// happen to that request since.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SentWatch {
    /// When it was sent, by this tab's clock.
    pub sent_at_ms: u64,
    /// The entry that carried it and the height it was dated at, which is what
    /// its fate in the inbox is read back by.
    pub entry_key: EntryKey,
    pub mainnet_height: u32,
    /// Whether this tab has seen the bridge remove the entry, which it does
    /// when it reads it.
    ///
    /// Remembered because the evidence does not last. About half an hour after
    /// the bridge reads an entry, the inbox floor passes its height, and the
    /// entry and the record of its removal are both pruned. From then on a
    /// request the bridge read looks exactly like one that was dropped unread,
    /// and without this every order would be re-requested every half hour.
    pub read: bool,
}

impl SentWatch {
    /// A request just sent in `entry`.
    pub fn sent(entry: &WireEntry, now_ms: u64) -> Self {
        SentWatch {
            sent_at_ms: now_ms,
            entry_key: entry.entry.key(),
            mainnet_height: entry.entry.mainnet_height,
            read: false,
        }
    }

    /// Record it if `inbox` shows the bridge has read this request.
    pub fn observe(&mut self, inbox: &InboxStateV1) {
        if inbox.is_removed(&self.entry_key, self.mainnet_height) {
            self.read = true;
        }
    }
}

/// Whether a watch request for a script should be sent now, given what this
/// tab last sent about it (`None` if nothing) and the inbox as the node serves
/// it.
///
/// Due when it was never sent, when the last request is old enough to renew,
/// or when the last request left the inbox without the bridge having read it.
/// Not due while a request is still waiting in the inbox, once the bridge is
/// seen to have read it, or while a just-sent request may still be landing.
pub fn watch_due(sent: Option<&SentWatch>, inbox: &InboxStateV1, now_ms: u64) -> bool {
    let Some(sent) = sent else {
        return true;
    };
    let age = now_ms.saturating_sub(sent.sent_at_ms);
    if age >= RENEW_AFTER_MS {
        return true;
    }
    if sent.read || inbox.is_removed(&sent.entry_key, sent.mainnet_height) {
        return false;
    }
    if age < LAND_GRACE_MS {
        return false;
    }
    !inbox.entries.contains_key(&sent.entry_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use freenet_bitcoin_common::from_cbor;
    use freenet_bitcoin_inbox::test_support::{TestAuthority, TestGhostkey};
    use freenet_bitcoin_inbox::{InboxStateV1, WINDOW_BLOCKS};
    use freenet_stdlib::prelude::{ContractCode, ContractInstanceId};
    use ghostkey_common::{ScopedPayload, SignatureRequestor};
    use std::sync::OnceLock;

    const FLOOR: u32 = 900_000;

    /// Minting a notary key costs an RSA key generation, so once per binary.
    fn authority() -> &'static TestAuthority {
        static A: OnceLock<TestAuthority> = OnceLock::new();
        A.get_or_init(TestAuthority::new)
    }

    fn bridge_key() -> SigningKey {
        SigningKey::from_bytes(&[3u8; 32])
    }

    fn bridge() -> BridgeId {
        BridgeId(bridge_key().verifying_key().to_bytes())
    }

    /// An inbox the test bridge has opened at `FLOOR`, under the test authority.
    fn open_inbox() -> InboxStateV1 {
        let mut s = InboxStateV1::default();
        s.apply_delta(
            &authority().params(bridge()),
            &InboxDelta {
                floor: Some(SignedFloor::sign(&bridge_key(), FLOOR)),
                entries: vec![],
                removals: vec![],
            },
        )
        .expect("the bridge opens its inbox");
        s
    }

    /// What the ghostkey delegate does with `signing_payload`: wrap it in a
    /// scoped payload naming the web app that asked, and sign that.
    fn signed(gk: &TestGhostkey, signing_payload: Vec<u8>) -> WireEntry {
        let scoped = to_cbor(&ScopedPayload {
            requestor: SignatureRequestor::WebApp(ContractInstanceId::new([7u8; 32])),
            payload: signing_payload,
        })
        .expect("scoped payload encodes");
        let sig = gk.sk.sign(&scoped).to_bytes().to_vec();
        WireEntry::from_sign_result(gk.pem.clone(), scoped, sig).expect("a signed entry forms")
    }

    fn watch_one() -> InboxRequest {
        watch_requests(
            BitcoinNetwork::Signet,
            &[vec![0x00, 0x14, 0xab]],
            1_000,
            None,
        )
        .pop()
        .expect("one request")
    }

    /// Submit through the same bytes the UI would send, as the contract would
    /// receive them.
    fn submit(state: &mut InboxStateV1, floor: &SignedFloor, entry: WireEntry) {
        let bytes = submission_bytes(floor, entry).expect("submission encodes");
        let delta: InboxDelta = from_cbor(&bytes).expect("submission decodes");
        state
            .apply_delta(&authority().params(bridge()), &delta)
            .expect("the inbox accepts the update");
    }

    /// The whole path, end to end on real pieces: prepared here, signed as the
    /// ghostkey delegate signs, submitted as the UI submits, admitted by the
    /// real inbox contract logic, and opened by the real bridge key.
    #[test]
    fn a_prepared_entry_is_admitted_by_the_inbox_and_opened_by_the_bridge() {
        let gk = authority().mint();
        let floor = SignedFloor::sign(&bridge_key(), FLOOR);
        let request = watch_one();
        let prepared = prepare_entry(bridge(), gk.id(), &floor, &request).expect("prepares");

        let mut inbox = open_inbox();
        submit(&mut inbox, &floor, signed(&gk, prepared.signing_payload));
        assert_eq!(inbox.entries.len(), 1, "the inbox admits the entry");

        let entry = inbox.entries.values().next().expect("the admitted entry");
        let body = entry.body().expect("the body decodes");
        let opened = freenet_bitcoin_inbox::seal::unseal(
            &bridge_key(),
            &gk.id(),
            entry.mainnet_height,
            &body.sealed,
        )
        .expect("the bridge opens it");
        assert_eq!(
            opened, request,
            "and reads exactly the request that was sent"
        );

        let stranger = authority().mint();
        assert!(
            freenet_bitcoin_inbox::seal::unseal(
                &bridge_key(),
                &stranger.id(),
                entry.mainnet_height,
                &body.sealed
            )
            .is_err(),
            "a request sealed for one Ghost Key does not open as another's"
        );
    }

    /// The trap in the issue as first written: dating by the chain tip. The
    /// floor trails the tip, so a tip-dated entry falls above the window, and
    /// the inbox drops it with no error. Only the floor-dated one gets in.
    #[test]
    fn an_entry_is_dated_against_the_floor_and_one_dated_by_the_tip_goes_nowhere() {
        let gk = authority().mint();
        let floor = SignedFloor::sign(&bridge_key(), FLOOR);
        let request = watch_one();

        let prepared = prepare_entry(bridge(), gk.id(), &floor, &request).expect("prepares");
        assert!(
            (FLOOR..=FLOOR + WINDOW_BLOCKS).contains(&prepared.mainnet_height),
            "dated inside the window above the floor"
        );

        // Built the same way, but dated as a tip a little ahead of the floor.
        let tip = FLOOR + WINDOW_BLOCKS + 26;
        let sealed =
            freenet_bitcoin_inbox::seal::seal(&bridge(), &gk.id(), tip, &request).expect("seals");
        let tip_payload = InboxEntryBody {
            bridge: bridge(),
            mainnet_height: tip,
            sealed,
        }
        .signing_payload()
        .expect("lays out");

        let mut inbox = open_inbox();
        submit(&mut inbox, &floor, signed(&gk, tip_payload));
        assert!(
            inbox.entries.is_empty(),
            "a tip-dated entry is dropped, and the update still reports success"
        );
        submit(&mut inbox, &floor, signed(&gk, prepared.signing_payload));
        assert_eq!(inbox.entries.len(), 1, "the floor-dated one is admitted");
    }

    #[test]
    fn watch_requests_split_at_the_script_limit_and_each_is_dated_later() {
        let scripts: Vec<Vec<u8>> = (0..=MAX_SCRIPTS_PER_REQUEST as u8)
            .map(|i| vec![0x00, 0x14, i])
            .collect();
        let requests = watch_requests(BitcoinNetwork::Bitcoin, &scripts, 5_000, Some(12));

        assert_eq!(
            requests.len(),
            2,
            "one past the limit makes a second request"
        );
        assert_eq!(requests[0].scripts.len(), MAX_SCRIPTS_PER_REQUEST);
        assert_eq!(requests[1].scripts.len(), 1);
        assert!(
            requests[0].made_at_ms < requests[1].made_at_ms,
            "strictly later, so the bridge applies both"
        );
        for r in &requests {
            assert_eq!(r.action, Action::Watch);
            assert_eq!(r.network, BitcoinNetwork::Bitcoin);
            assert_eq!(r.scan_from_height, Some(12));
            r.check().expect("every request is one the inbox accepts");
        }
    }

    #[test]
    fn a_script_named_twice_is_asked_for_once() {
        let s = vec![0x00, 0x14, 0x01];
        let requests = watch_requests(BitcoinNetwork::Signet, &[s.clone(), s], 1, None);
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].scripts.len(), 1);
    }

    #[test]
    fn the_next_timestamp_never_goes_back() {
        assert_eq!(
            next_made_at_ms(100, None),
            100,
            "the clock, with no history"
        );
        assert_eq!(next_made_at_ms(100, Some(50)), 100, "the clock, once past");
        assert_eq!(
            next_made_at_ms(100, Some(100)),
            101,
            "never equal to the last"
        );
        assert_eq!(
            next_made_at_ms(100, Some(200)),
            201,
            "past a clock that ran ahead and came back"
        );
    }

    /// The key built from a generation pointer's code hash must be the very
    /// contract the bridge serves, or every request goes to a contract nobody
    /// reads. The bridge side is built here the way the bridge's own
    /// `InboxWorker::contract_key` builds it, independently of this module:
    /// derived from the parameters through its own encoder, so a mistake in
    /// `inbox_params_bytes` cannot appear on both sides and cancel out.
    #[test]
    fn the_inbox_key_is_the_one_the_bridge_serves() {
        let code = ContractCode::from(b"stands in for the inbox wasm".to_vec());
        let bridge_params = freenet_bitcoin_common::to_cbor(&InboxParameters::production(bridge()))
            .expect("the bridge's parameters encode");
        let the_bridges = ContractKey::from_params_and_code(Parameters::from(bridge_params), &code);

        let ours = inbox_contract_key(bridge(), *code.hash()).expect("key builds");
        assert_eq!(ours.id(), the_bridges.id(), "same instance id");
        assert_eq!(ours.code_hash(), the_bridges.code_hash(), "same code hash");
    }

    const T0: u64 = 1_700_000_000_000;

    /// A signed entry for one watch, as sent, and the bridge's floor it was
    /// dated against.
    fn a_sent_entry() -> WireEntry {
        let gk = authority().mint();
        let floor = SignedFloor::sign(&bridge_key(), FLOOR);
        let prepared = prepare_entry(bridge(), gk.id(), &floor, &watch_one()).expect("prepares");
        signed(&gk, prepared.signing_payload)
    }

    fn apply(inbox: &mut InboxStateV1, delta: InboxDelta) {
        inbox
            .apply_delta(&authority().params(bridge()), &delta)
            .expect("the inbox accepts the update");
    }

    /// The bridge reading `entry`: it signs a batch removing it.
    fn bridge_reads(inbox: &mut InboxStateV1, entry: &WireEntry) {
        let mut removed = std::collections::BTreeSet::new();
        removed.insert(entry.entry.key().removal_prefix());
        apply(
            inbox,
            InboxDelta {
                floor: Some(SignedFloor::sign(&bridge_key(), FLOOR)),
                entries: vec![],
                removals: vec![freenet_bitcoin_inbox::RemovalBatch::sign(
                    &bridge_key(),
                    entry.entry.mainnet_height,
                    &removed,
                )],
            },
        );
    }

    /// The bridge's floor moving past `entry`, which prunes it and any record
    /// of its removal.
    fn floor_passes(inbox: &mut InboxStateV1, entry: &WireEntry) {
        apply(
            inbox,
            InboxDelta {
                floor: Some(SignedFloor::sign(
                    &bridge_key(),
                    entry.entry.mainnet_height + 1,
                )),
                entries: vec![],
                removals: vec![],
            },
        );
    }

    #[test]
    fn a_script_never_asked_for_is_due() {
        assert!(watch_due(None, &open_inbox(), T0));
    }

    #[test]
    fn a_request_still_waiting_in_the_inbox_is_not_due() {
        let entry = a_sent_entry();
        let mut inbox = open_inbox();
        submit(
            &mut inbox,
            &SignedFloor::sign(&bridge_key(), FLOOR),
            entry.clone(),
        );
        let sent = SentWatch::sent(&entry, T0);
        assert!(!watch_due(Some(&sent), &inbox, T0 + 10 * 60 * 1000));
    }

    #[test]
    fn a_just_sent_request_is_given_time_to_land() {
        let entry = a_sent_entry();
        let sent = SentWatch::sent(&entry, T0);
        assert!(
            !watch_due(Some(&sent), &open_inbox(), T0 + 1_000),
            "not in the inbox yet, but only a second old"
        );
    }

    #[test]
    fn a_request_the_bridge_read_is_not_due() {
        let entry = a_sent_entry();
        let mut inbox = open_inbox();
        submit(
            &mut inbox,
            &SignedFloor::sign(&bridge_key(), FLOOR),
            entry.clone(),
        );
        bridge_reads(&mut inbox, &entry);
        let sent = SentWatch::sent(&entry, T0);
        assert!(!watch_due(Some(&sent), &inbox, T0 + 10 * 60 * 1000));
    }

    #[test]
    fn a_request_that_left_the_inbox_unread_is_due_again() {
        let entry = a_sent_entry();
        let sent = SentWatch::sent(&entry, T0);
        assert!(
            watch_due(Some(&sent), &open_inbox(), T0 + 10 * 60 * 1000),
            "past the grace period, not in the inbox, never seen read"
        );
    }

    /// The trap this type exists for. Once the bridge has read a request, the
    /// floor passing it erases both the entry and the record that it was read,
    /// so read and dropped look the same. A watch whose read was observed is
    /// not asked for again; the same history unobserved would be, every half
    /// hour, for every order.
    #[test]
    fn a_request_seen_read_is_not_resent_once_the_floor_erases_the_evidence() {
        let entry = a_sent_entry();
        let mut inbox = open_inbox();
        submit(
            &mut inbox,
            &SignedFloor::sign(&bridge_key(), FLOOR),
            entry.clone(),
        );
        bridge_reads(&mut inbox, &entry);

        let mut observed = SentWatch::sent(&entry, T0);
        observed.observe(&inbox);
        assert!(observed.read, "the removal was seen");
        let unobserved = SentWatch::sent(&entry, T0);

        floor_passes(&mut inbox, &entry);
        let later = T0 + 40 * 60 * 1000;
        assert!(
            !inbox.is_removed(&entry.entry.key(), entry.entry.mainnet_height)
                && !inbox.entries.contains_key(&entry.entry.key()),
            "the floor has erased every trace of it"
        );
        assert!(
            !watch_due(Some(&observed), &inbox, later),
            "seen read: not resent"
        );
        assert!(
            watch_due(Some(&unobserved), &inbox, later),
            "the same history, unobserved, would be resent"
        );
    }

    #[test]
    fn a_watch_is_renewed_before_the_bridge_lets_it_lapse() {
        let entry = a_sent_entry();
        let mut sent = SentWatch::sent(&entry, T0);
        sent.read = true;
        assert!(!watch_due(
            Some(&sent),
            &open_inbox(),
            T0 + RENEW_AFTER_MS - 1
        ));
        assert!(watch_due(Some(&sent), &open_inbox(), T0 + RENEW_AFTER_MS));
    }
}
