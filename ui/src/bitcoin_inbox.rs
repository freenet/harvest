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
    sender_height, Action, ByteBuf, GhostkeyId, InboxDelta, InboxEntryBody, InboxParameters,
    InboxRequest, SignedFloor, WireEntry, MAX_SCRIPTS_PER_REQUEST,
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
}
