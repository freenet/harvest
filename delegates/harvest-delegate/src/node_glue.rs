//! What the node hands this delegate, decoded here rather than by the
//! `#[delegate]` macro, and the manifest that asks for background runs.
//!
//! # Why this is not the macro
//!
//! A node runs a delegate with no tab open in three ways, from freenet-core
//! #5730 (lifecycle) and #5747 (wake-ups, not in a release yet): once when
//! it is installed, once each time the node starts, and on a schedule the
//! delegate declares (a wake-up). The delegate
//! declares which it wants in a manifest, a WASM custom section named
//! `freenet-manifest`, and the node delivers them as two new inbound
//! messages, `WakeupFired` (bincode tag 9) and `Lifecycle` (tag 10).
//!
//! stdlib 0.12 has both and a macro that writes the manifest. Harvest cannot
//! move to it yet: `freenet-migrate` 0.6 and `ghostkey-common` 0.3, the
//! latest of each, are built on stdlib 0.8, so a 0.12 Harvest links two
//! incompatible copies and does not compile. So this delegate stays on 0.8.5
//! and does the two things the 0.12 macro would:
//!
//! 1. [`MANIFEST_JSON`] is embedded as the `freenet-manifest` custom section,
//!    byte for byte what the 0.12 macro emits for the same declaration.
//! 2. [`process`] is the exported entry point the 0.8.5 macro generates,
//!    except that an inbound message 0.8.5 cannot decode is tried as tag 9 or
//!    tag 10 before it is refused.
//!
//! Nothing else differs: parameters, origin, the context handle and the
//! result are read and written exactly as the 0.8.5 macro does. Every other
//! message goes to [`crate::HarvestDelegate`]'s `DelegateInterface::process`,
//! as before.
//!
//! # On a node that predates wake-ups
//!
//! freenet-core v0.2.138 reads the manifest with stdlib 0.12.0, which ignores
//! the `wakeups` field it does not know and keeps the rest: the delegate is
//! installed and started there as on a newer node, and simply never receives
//! a wake-up. An older node ignores the custom section altogether. Neither
//! sends tag 9 or 10 to a delegate whose manifest does not ask, so this
//! decoding only ever runs on a node that does.
//!
//! The byte layouts below are pinned by tests against bytes produced by
//! stdlib 0.12.0's own serializer (see `tests` for how they were made).

use serde::Deserialize;

/// The manifest, as JSON. The node sends `Installed` and `NodeStarted`, and
/// a `heartbeat` wake-up every five minutes, once the user has granted
/// Harvest's delegate background runs (the consent card of #5730).
///
/// Field for field what stdlib 0.12.1's `#[delegate(manifest(lifecycle =
/// [Installed, NodeStarted], capabilities = [Background], wakeups =
/// [heartbeat = 300]))]` writes; a reader keys on names, not order.
#[cfg_attr(not(any(test, target_family = "wasm")), allow(dead_code))]
pub(crate) const MANIFEST_JSON: &str = concat!(
    r#"{"manifest_version":1,"#,
    r#""lifecycle":["installed","node_started"],"#,
    r#""capabilities":["background"],"#,
    r#""wakeups":[{"tag":"heartbeat","every_secs":300}]}"#
);

/// The tag of the one wake-up [`MANIFEST_JSON`] declares.
pub(crate) const HEARTBEAT_TAG: &[u8] = b"heartbeat";

/// The manifest as the custom section's payload. `concat!` gives a `&str`
/// and a `#[link_section]` static must be an array, so the bytes are copied
/// in at compile time.
#[cfg(all(feature = "freenet-main-delegate", target_family = "wasm"))]
#[used]
#[link_section = "freenet-manifest"]
static FREENET_DELEGATE_MANIFEST: [u8; MANIFEST_JSON.len()] = manifest_bytes();

#[cfg(all(feature = "freenet-main-delegate", target_family = "wasm"))]
const fn manifest_bytes() -> [u8; MANIFEST_JSON.len()] {
    let src = MANIFEST_JSON.as_bytes();
    let mut out = [0u8; MANIFEST_JSON.len()];
    let mut i = 0;
    while i < src.len() {
        out[i] = src[i];
        i += 1;
    }
    out
}

/// A run the node starts on its own, with no tab and no contract change
/// behind it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum BackgroundRun {
    /// A wake-up the manifest declared, by its tag.
    Wakeup { tag: Vec<u8> },
    /// Installed on this node, or its Background grant first given.
    Installed,
    /// The node started. Contract notifications sent while it was down were
    /// not delivered, and subscriptions may not have survived.
    NodeStarted,
}

/// What an inbound message decoded to.
pub(crate) enum Inbound<'a> {
    /// Anything stdlib 0.8.5 knows: the delegate's ordinary messages.
    Known(freenet_stdlib::prelude::InboundDelegateMsg<'a>),
    Background(BackgroundRun),
}

/// The tags stdlib 0.12 appended after the eight 0.8.5 knows, in their wire
/// order. Only the variant INDEX matters to bincode, so the first nine are
/// placeholders that are never accepted: a message 0.8.5 failed to decode
/// with one of those indexes is malformed, not newer.
#[derive(Deserialize)]
enum Newer {
    _0,
    _1,
    _2,
    _3,
    _4,
    _5,
    _6,
    _7,
    _8,
    WakeupFired { tag: Vec<u8> },
    Lifecycle(Lifecycle),
}

#[derive(Deserialize)]
enum Lifecycle {
    Installed,
    NodeStarted {
        #[allow(dead_code)]
        down_since_ms: Option<u64>,
    },
}

/// Decode an inbound message: as stdlib 0.8.5 does, or else as one of the
/// two background runs, or the 0.8.5 error.
pub(crate) fn decode_inbound(bytes: &[u8]) -> Result<Inbound<'_>, String> {
    use freenet_stdlib::prelude::bincode;
    let known = match bincode::deserialize(bytes) {
        Ok(msg) => return Ok(Inbound::Known(msg)),
        Err(e) => e.to_string(),
    };
    match bincode::deserialize::<Newer>(bytes) {
        Ok(Newer::WakeupFired { tag }) => Ok(Inbound::Background(BackgroundRun::Wakeup { tag })),
        Ok(Newer::Lifecycle(Lifecycle::Installed)) => {
            Ok(Inbound::Background(BackgroundRun::Installed))
        }
        Ok(Newer::Lifecycle(Lifecycle::NodeStarted { .. })) => {
            Ok(Inbound::Background(BackgroundRun::NodeStarted))
        }
        _ => Err(known),
    }
}

/// The delegate's exported entry point: the 0.8.5 macro's, with
/// [`decode_inbound`] in place of its plain decode. See the module docs.
#[no_mangle]
#[cfg(feature = "freenet-main-delegate")]
pub extern "C" fn process(parameters: i64, origin: i64, inbound: i64) -> i64 {
    use freenet_stdlib::prelude::{
        bincode, DelegateCtx, DelegateError, DelegateInterface, DelegateInterfaceResult,
        MessageOrigin, OutboundDelegateMsg, Parameters,
    };
    let parameters = unsafe {
        let param_buf = &*(parameters as *const freenet_stdlib::memory::buf::BufferBuilder);
        let bytes = &*std::ptr::slice_from_raw_parts(param_buf.start(), param_buf.bytes_written());
        Parameters::from(bytes)
    };
    let origin: Option<MessageOrigin> = unsafe {
        let origin_buf = &*(origin as *const freenet_stdlib::memory::buf::BufferBuilder);
        let bytes =
            &*std::ptr::slice_from_raw_parts(origin_buf.start(), origin_buf.bytes_written());
        if bytes.is_empty() {
            None
        } else {
            bincode::deserialize(bytes).ok()
        }
    };
    let inbound = unsafe {
        let inbound_buf = &mut *(inbound as *mut freenet_stdlib::memory::buf::BufferBuilder);
        let bytes =
            &*std::ptr::slice_from_raw_parts(inbound_buf.start(), inbound_buf.bytes_written());
        match decode_inbound(bytes) {
            Ok(v) => v,
            Err(err) => {
                return DelegateInterfaceResult::from(Err::<Vec<OutboundDelegateMsg>, _>(
                    DelegateError::Deser(err),
                ))
                .into_raw()
            }
        }
    };
    // SAFETY: as in the macro: the runtime has set up the delegate execution
    // environment before calling this function, so the host functions the
    // context uses are available.
    let mut ctx = unsafe { DelegateCtx::__new() };
    let result = match inbound {
        Inbound::Known(msg) => <crate::HarvestDelegate as DelegateInterface>::process(
            &mut ctx, parameters, origin, msg,
        ),
        Inbound::Background(run) => crate::background::run(&mut ctx, run, crate::now_ms()),
    };
    let bytes = encode_result(&result);
    let raw = RawResult {
        ptr: bytes.as_ptr() as i64,
        size: bytes.len() as u32,
    };
    std::mem::forget(bytes);
    Box::into_raw(Box::new(raw)) as i64
}

/// `freenet_stdlib::prelude::DelegateInterfaceResult`'s layout (`#[repr(C)]`,
/// fields private there): where the result's bytes start and how many.
#[cfg(feature = "freenet-main-delegate")]
#[repr(C)]
struct RawResult {
    ptr: i64,
    size: u32,
}

/// `bincode::serialize(result)`, byte for byte, with every application
/// message's payload copied in one piece (#206).
///
/// `ApplicationMessage::payload` is a plain `Vec<u8>`, so serde hands bincode
/// one byte at a time; on a large answer (a full export runs to megabytes)
/// that per-byte path cost a whole call's budget by itself. Bincode writes a
/// `Vec<u8>` as its `u64` length and the raw bytes however it is reached, so
/// writing them directly is the same encoding. Everything else goes through
/// bincode as before. `the_result_encoding_is_bincodes` pins the equality.
pub(crate) fn encode_result(
    result: &Result<
        Vec<freenet_stdlib::prelude::OutboundDelegateMsg>,
        freenet_stdlib::prelude::DelegateError,
    >,
) -> Vec<u8> {
    use freenet_stdlib::prelude::{bincode, OutboundDelegateMsg};
    let Ok(messages) = result else {
        return bincode::serialize(result).expect("a delegate error encodes");
    };
    let payloads: usize = messages
        .iter()
        .map(|m| match m {
            OutboundDelegateMsg::ApplicationMessage(a) => a.payload.len(),
            _ => 0,
        })
        .sum();
    let mut out = Vec::with_capacity(payloads + 64 * messages.len() + 12);
    out.extend_from_slice(&0u32.to_le_bytes()); // Ok
    out.extend_from_slice(&(messages.len() as u64).to_le_bytes());
    for message in messages {
        match message {
            OutboundDelegateMsg::ApplicationMessage(a) => {
                out.extend_from_slice(&0u32.to_le_bytes()); // ApplicationMessage
                out.extend_from_slice(&(a.payload.len() as u64).to_le_bytes());
                out.extend_from_slice(&a.payload);
                out.extend_from_slice(
                    &bincode::serialize(&a.context).expect("a delegate context encodes"),
                );
                out.push(u8::from(a.processed));
            }
            other => out.extend_from_slice(
                &bincode::serialize(other).expect("an outbound message encodes"),
            ),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // Produced by stdlib 0.12.0's own serializer (`bincode::serialize` of
    // `InboundDelegateMsg`), the version freenet-core v0.2.138 links, with a
    // scratch crate kept at ~/code/tmp/harvest-wire-fixtures. The same crate
    // reads MANIFEST_JSON with 0.12.0's `DelegateManifest` and gets
    // lifecycle [Installed, NodeStarted] and capabilities [Background].
    const WAKEUP_HEARTBEAT: &str = "090000000900000000000000686561727462656174";
    const INSTALLED: &str = "0a00000000000000";
    const NODE_STARTED_SOME: &str = "0a000000010000000100505c18a3010000";
    const NODE_STARTED_NONE: &str = "0a0000000100000000";

    fn background(hex: &str) -> BackgroundRun {
        match decode_inbound(&unhex(hex)) {
            Ok(Inbound::Background(run)) => run,
            Ok(Inbound::Known(msg)) => panic!("decoded as a 0.8.5 message: {msg:?}"),
            Err(e) => panic!("refused: {e}"),
        }
    }

    /// The two messages stdlib 0.12 appended decode to the runs they are.
    /// Mutated red by dropping the fallback decode, and by swapping the two
    /// lifecycle arms.
    #[test]
    fn the_newer_messages_decode_as_the_node_sends_them() {
        assert_eq!(
            background(WAKEUP_HEARTBEAT),
            BackgroundRun::Wakeup {
                tag: HEARTBEAT_TAG.to_vec()
            }
        );
        assert_eq!(background(INSTALLED), BackgroundRun::Installed);
        assert_eq!(background(NODE_STARTED_SOME), BackgroundRun::NodeStarted);
        assert_eq!(background(NODE_STARTED_NONE), BackgroundRun::NodeStarted);
    }

    /// Every message 0.8.5 knows still decodes as it did, and a malformed
    /// one is refused with 0.8.5's own error rather than read as a
    /// placeholder. Mutated red by accepting the placeholders.
    #[test]
    fn known_messages_are_unchanged_and_junk_is_refused() {
        use freenet_stdlib::prelude::{bincode, ApplicationMessage, InboundDelegateMsg};
        let msg = InboundDelegateMsg::ApplicationMessage(ApplicationMessage::new(vec![1, 2, 3]));
        let bytes = bincode::serialize(&msg).unwrap();
        assert!(matches!(
            decode_inbound(&bytes),
            Ok(Inbound::Known(InboundDelegateMsg::ApplicationMessage(_)))
        ));
        // Tag 0 with its payload cut off: 0.8.5 refuses it, and so must we.
        assert!(decode_inbound(&bytes[..6]).is_err());
        // A tag past the newest one.
        assert!(decode_inbound(&[11, 0, 0, 0]).is_err());
        assert!(decode_inbound(&[]).is_err());
    }

    /// The manifest asks for exactly what the delegate handles.
    #[test]
    fn the_manifest_asks_for_what_the_delegate_handles() {
        let json: freenet_stdlib::prelude::serde_json::Value =
            freenet_stdlib::prelude::serde_json::from_str(MANIFEST_JSON).expect("valid JSON");
        assert_eq!(json["manifest_version"], 1);
        assert_eq!(
            json["lifecycle"],
            freenet_stdlib::prelude::serde_json::json!(["installed", "node_started"])
        );
        assert_eq!(
            json["capabilities"],
            freenet_stdlib::prelude::serde_json::json!(["background"])
        );
        assert_eq!(
            json["wakeups"],
            freenet_stdlib::prelude::serde_json::json!([{ "tag": "heartbeat", "every_secs": 300 }])
        );
        assert_eq!(
            json["wakeups"][0]["tag"].as_str().unwrap().as_bytes(),
            HEARTBEAT_TAG
        );
    }

    /// The answer bytes are bincode's, whatever mix of messages, and for an
    /// error. Mutated red by writing the payload without its length, or
    /// dropping `processed`.
    #[test]
    fn the_result_encoding_is_bincodes() {
        use freenet_stdlib::prelude::{
            ApplicationMessage, ContractInstanceId, DelegateContext, DelegateError,
            GetContractRequest, OutboundDelegateMsg,
        };
        let mut get = GetContractRequest::new(ContractInstanceId::new([7; 32]));
        get.context = DelegateContext::new(vec![1, 2, 3]);
        let mut with_context = ApplicationMessage::new((0..70_000).map(|i| i as u8).collect());
        with_context.context = DelegateContext::new(vec![9; 40]);
        let cases: Vec<Result<Vec<OutboundDelegateMsg>, DelegateError>> = vec![
            Ok(vec![]),
            Ok(vec![OutboundDelegateMsg::ApplicationMessage(
                ApplicationMessage::new(vec![]).processed(true),
            )]),
            Ok(vec![
                OutboundDelegateMsg::ApplicationMessage(with_context),
                OutboundDelegateMsg::GetContractRequest(get),
                OutboundDelegateMsg::ApplicationMessage(ApplicationMessage::new(vec![24; 300])),
            ]),
            Err(DelegateError::Other("no".into())),
        ];
        for case in cases {
            assert_eq!(
                encode_result(&case),
                freenet_stdlib::prelude::bincode::serialize(&case).unwrap()
            );
        }
    }
}
