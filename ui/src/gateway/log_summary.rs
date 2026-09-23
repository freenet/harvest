//! One-line, secret-free descriptions of delegate traffic, for logs.
//!
//! # Why this module exists (harvest#94)
//!
//! The UI used to log every delegate response with `{:?}` at `info!`, which
//! release builds keep, and several responses carry secrets: conversation
//! keys, backup strings, the payment xpub, a vault `SignResult`'s signature,
//! a vault export's signing key. The protocol types in `harvest-common` now
//! redact themselves, but `GhostkeyResponse` and freenet-stdlib's types
//! derive `Debug` upstream where Harvest cannot change it, and a log line is
//! not the place to find out whether the next secret-bearing field
//! remembered to redact.
//!
//! So a delegate or host response is logged ONLY through these functions,
//! which print a variant name and the request id or Ghost Key fingerprint it
//! concerns, and nothing else. The call-site guard in `gateway::log_scan`
//! (test-only) holds the UI's source to that; its module docs say exactly
//! which macro and call shapes it covers.
//!
//! The enums are `#[non_exhaustive]` from here, so each match has a wildcard;
//! it prints no fields, which makes a variant added upstream safe by default.

use freenet_stdlib::client_api::HostResponse;
use harvest_common::{BitcoinDelegateResponse, HarvestDelegateResponse};

/// `name`, or `name (id)`.
fn line(name: &str, id: Option<String>) -> String {
    match id {
        Some(id) => format!("{name} ({id})"),
        None => name.to_string(),
    }
}

/// A harvest delegate response, for a log.
pub(crate) fn harvest_response_summary(response: &HarvestDelegateResponse) -> String {
    use HarvestDelegateResponse as R;
    let request = |id: &u64| Some(format!("request {id}"));
    #[allow(clippy::wildcard_enum_match_arm)]
    let (name, id) = match response {
        R::RsaPublicKey {
            ghostkey_fingerprint,
            ..
        } => ("RsaPublicKey", Some(ghostkey_fingerprint.clone())),
        R::EncryptionKeyReady {
            ghostkey_fingerprint,
            ..
        } => ("EncryptionKeyReady", Some(ghostkey_fingerprint.clone())),
        R::EncryptionKeyAbsent {
            ghostkey_fingerprint,
        } => ("EncryptionKeyAbsent", Some(ghostkey_fingerprint.clone())),
        R::PredecessorMarker { .. } => ("PredecessorMarker", None),
        R::PredecessorMarkerRecorded { .. } => ("PredecessorMarkerRecorded", None),
        R::MigratedSecretImported { .. } => ("MigratedSecretImported", None),
        R::BuyerConversationStored { request_id, .. } => {
            ("BuyerConversationStored", request(request_id))
        }
        R::BuyerConversationList { request_id, .. } => {
            ("BuyerConversationList", request(request_id))
        }
        R::BuyerConversationExported { request_id, .. } => {
            ("BuyerConversationExported", request(request_id))
        }
        R::BuyerConversationImported { request_id, .. } => {
            ("BuyerConversationImported", request(request_id))
        }
        R::BuyerConversationMarkedBackedUp { request_id, .. } => {
            ("BuyerConversationMarkedBackedUp", request(request_id))
        }
        R::BuyerConversationForgotten { request_id, .. } => {
            ("BuyerConversationForgotten", request(request_id))
        }
        R::ConversationKeys {
            request_id,
            ghostkey_fingerprint,
            ..
        } => (
            "ConversationKeys",
            Some(format!("request {request_id}, {ghostkey_fingerprint}")),
        ),
        R::ListingCreated { request_id, .. } => ("ListingCreated", request(request_id)),
        R::ContractUpdate { .. } => ("ContractUpdate", None),
        R::ContractState { .. } => ("ContractState", None),
        R::StoreRegistered {
            ghostkey_fingerprint,
        } => ("StoreRegistered", Some(ghostkey_fingerprint.clone())),
        R::StoreList {
            ghostkey_fingerprint,
            ..
        } => ("StoreList", Some(ghostkey_fingerprint.clone())),
        R::RememberedStores { .. } => ("RememberedStores", None),
        R::KeptPurchases { .. } => ("KeptPurchases", None),
        R::KeepPurchaseRefused { order_id, .. } => ("KeepPurchaseRefused", Some(order_id.short())),
        R::MigrationMarker { .. } => ("MigrationMarker", None),
        R::MigrationMarkerRecorded { .. } => ("MigrationMarkerRecorded", None),
        R::Error { .. } => ("Error", None),
        _ => ("an unrecognised HarvestDelegateResponse variant", None),
    };
    line(name, id)
}

/// A response on the harvest delegate's Bitcoin surface, for a log.
///
/// Nothing here is a spending key, but the payment xpub names every address
/// a seller will be paid at, so `PaymentXpub`/`PaymentXpubSet` print no
/// fields at all.
pub(crate) fn bitcoin_response_summary(response: &BitcoinDelegateResponse) -> String {
    use BitcoinDelegateResponse as R;
    let request = |id: &u64| Some(format!("request {id}"));
    #[allow(clippy::wildcard_enum_match_arm)]
    let (name, id) = match response {
        R::Watched { request_id, .. } => ("Watched", request(request_id)),
        R::Unwatched { request_id, .. } => ("Unwatched", request(request_id)),
        R::WatchList { .. } => ("WatchList", None),
        R::OrderAssociated { request_id, .. } => ("OrderAssociated", request(request_id)),
        R::BridgeConfigured { request_id, .. } => ("BridgeConfigured", request(request_id)),
        R::Bridge { .. } => ("Bridge", None),
        R::PaymentXpubSet { request_id, .. } => ("PaymentXpubSet", request(request_id)),
        R::PaymentXpub { .. } => ("PaymentXpub", None),
        R::OrderAddress { request_id, .. } => ("OrderAddress", request(request_id)),
        _ => ("an unrecognised BitcoinDelegateResponse variant", None),
    };
    line(name, id)
}

/// A vault (ghostkey delegate) response, for a log: the variant and the
/// fingerprint it concerns.
///
/// `GhostkeyResponse`'s `Debug` is derived in `ghostkey-common`, where
/// Harvest cannot redact it, and it prints everything: a `SignResult`'s
/// signature (a secret once store-key custody derives a wrapping key from
/// one, harvest#93), an `ExportResult`'s signing key PEM, an
/// `ExportAllResult`'s every key. So a `GhostkeyResponse` is never formatted
/// whole anywhere in this app.
pub(crate) fn ghostkey_response_summary(response: &ghostkey_common::GhostkeyResponse) -> String {
    use ghostkey_common::GhostkeyResponse as G;
    let fp = |f: &String| Some(f.clone());
    #[allow(clippy::wildcard_enum_match_arm)]
    let (name, id) = match response {
        G::ImportResult { fingerprint, .. } => ("ImportResult", fp(fingerprint)),
        G::GhostKeyList { keys } => ("GhostKeyList", Some(format!("{} key(s)", keys.len()))),
        G::GhostKeyDetail { fingerprint, .. } => ("GhostKeyDetail", fp(fingerprint)),
        G::Certificate { fingerprint, .. } => ("Certificate", fp(fingerprint)),
        G::SignResult { .. } => ("SignResult", None),
        G::DefaultKeyResult { fingerprint } => ("DefaultKeyResult", fingerprint.clone()),
        G::DefaultKeySet { fingerprint } => ("DefaultKeySet", fp(fingerprint)),
        G::VerifyResult { .. } => ("VerifyResult", None),
        G::Deleted { fingerprint } => ("Deleted", fp(fingerprint)),
        G::LabelSet { fingerprint, .. } => ("LabelSet", fp(fingerprint)),
        G::PermissionGranted { fingerprint, .. } => ("PermissionGranted", fp(fingerprint)),
        G::PermissionRevoked { fingerprint, .. } => ("PermissionRevoked", fp(fingerprint)),
        G::PermissionList { fingerprint, .. } => ("PermissionList", fp(fingerprint)),
        G::ExportResult { fingerprint, .. } => ("ExportResult", fp(fingerprint)),
        G::ExportAllResult { keys } => ("ExportAllResult", Some(format!("{} key(s)", keys.len()))),
        G::PermissionDenied { fingerprint, .. } => ("PermissionDenied", fp(fingerprint)),
        G::AccessDenied { .. } => ("AccessDenied", None),
        G::NoIdentityAvailable => ("NoIdentityAvailable", None),
        G::IdentityPresence { .. } => ("IdentityPresence", None),
        G::BackedUpMarked { fingerprint, .. } => ("BackedUpMarked", fp(fingerprint)),
        G::KeyNotFound { fingerprint } => ("KeyNotFound", fp(fingerprint)),
        G::Error { .. } => ("Error", None),
        _ => ("an unrecognised GhostkeyResponse variant", None),
    };
    line(name, id)
}

/// The variant of a host response, for a log.
///
/// Not `{:?}`: a `StreamChunk` is raw bytes of whatever is being streamed,
/// which can be a delegate's answer.
pub(crate) fn host_response_summary(response: &HostResponse) -> &'static str {
    #[allow(clippy::wildcard_enum_match_arm)]
    match response {
        HostResponse::ContractResponse(_) => "ContractResponse",
        HostResponse::DelegateResponse { .. } => "DelegateResponse",
        HostResponse::QueryResponse(_) => "QueryResponse",
        HostResponse::Ok => "Ok",
        HostResponse::StreamChunk { .. } => "StreamChunk",
        HostResponse::StreamHeader { .. } => "StreamHeader",
        _ => "an unrecognised HostResponse variant",
    }
}

/// A delegate's request for user input, for a log: its id and how many
/// answers it offers. The prompt text is the delegate's to show, through
/// the node's own UI, not ours to copy into a console.
pub(crate) fn user_input_summary(request: &freenet_stdlib::prelude::UserInputRequest) -> String {
    format!(
        "request {} ({} response option(s))",
        request.request_id,
        request.responses.len()
    )
}

/// What a payload that did not decode looked like, without its contents.
///
/// Not serde's error message: on version skew it quotes the offending value,
/// and in this protocol that can be a backup string, an xpub or a signing
/// key PEM. This names the CBOR enum variant, if the payload is one and the
/// name is a plain identifier, and the payload's length.
pub(crate) fn payload_shape(payload: &[u8]) -> String {
    let variant = harvest_common::from_cbor::<ciborium::Value>(payload)
        .ok()
        .and_then(|value| match value {
            // A unit variant is a bare string; any other is a one-entry map
            // keyed by the variant name.
            ciborium::Value::Text(name) => Some(name),
            ciborium::Value::Map(mut entries) if entries.len() == 1 => {
                match entries.pop().map(|(key, _)| key) {
                    Some(ciborium::Value::Text(name)) => Some(name),
                    _ => None,
                }
            }
            _ => None,
        })
        .filter(|name| {
            (1..=64).contains(&name.len())
                && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        });
    match variant {
        Some(name) => format!("variant `{name}`, {} bytes", payload.len()),
        None => format!("{} bytes", payload.len()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Bytes print as decimal under `{:?}` (0xA7 is 167); whitespace is
    /// dropped first so `{:#?}`'s one-element-per-line output still matches.
    fn leaks(printed: &str, secret_text: &str) -> bool {
        let squashed: String = printed.chars().filter(|c| !c.is_whitespace()).collect();
        squashed.contains(secret_text) || squashed.contains("167,167,167")
    }

    /// **A vault response is never logged whole** (harvest#94).
    ///
    /// `GhostkeyResponse`'s `Debug` is derived upstream and prints every
    /// field, which the first assertion confirms for each sample -- so the
    /// second one, on the summary the log line actually uses, is checking a
    /// real leak and not an empty one.
    #[test]
    fn a_vault_response_summary_prints_no_secret() {
        use ghostkey_common::{ExportedGhostKey, GhostkeyResponse as G};
        const SECRET: &str = "SECRET-SIGNING-KEY-PEM";
        let signature = vec![0xA7u8; 64];
        let samples = [
            (
                G::SignResult {
                    scoped_payload: vec![1u8; 8],
                    signature: signature.clone(),
                    certificate_pem: SECRET.into(),
                },
                "SignResult",
            ),
            (
                G::ExportResult {
                    fingerprint: "fp-one".into(),
                    certificate_pem: "cert".into(),
                    signing_key_pem: SECRET.into(),
                    label: None,
                },
                "ExportResult (fp-one)",
            ),
            (
                G::ExportAllResult {
                    keys: vec![ExportedGhostKey {
                        fingerprint: "fp-one".into(),
                        certificate_pem: "cert".into(),
                        signing_key_pem: SECRET.into(),
                        label: None,
                        notary_info: "notary".into(),
                    }],
                },
                "ExportAllResult (1 key(s))",
            ),
            (
                G::VerifyResult {
                    valid: true,
                    signer_fingerprint: None,
                    notary_info: None,
                    requestor: None,
                    message: Some(signature.clone()),
                },
                "VerifyResult",
            ),
        ];
        for (sample, expected) in samples {
            let whole = format!("{sample:?}");
            assert!(
                leaks(&whole, SECRET),
                "sample carries no secret to redact: {whole}"
            );
            let summary = ghostkey_response_summary(&sample);
            assert!(
                !leaks(&summary, SECRET),
                "the log summary printed a secret: {summary}"
            );
            assert_eq!(summary, expected);
        }
    }

    /// **The Bitcoin summaries print no xpub** (review of harvest#96).
    ///
    /// An exact match, not only a sentinel search, so a summary that starts
    /// printing any field fails even if that field redacts itself today.
    #[test]
    fn a_bitcoin_response_summary_prints_only_its_name_and_request() {
        use harvest_common::{BitcoinDelegateResponse as B, PaymentXpubStatus};
        const XPUB: &str = "vpubSECRETXPUB";
        let status = || PaymentXpubStatus {
            xpub: XPUB.into(),
            network: freenet_bitcoin_common::BitcoinNetwork::Signet,
            next_index: 3,
        };
        let samples = [
            (
                B::PaymentXpub {
                    status: Some(status()),
                },
                "PaymentXpub",
            ),
            (
                B::PaymentXpubSet {
                    request_id: 42,
                    result: Ok(status()),
                    matched_scripts: vec![],
                },
                "PaymentXpubSet (request 42)",
            ),
            (B::WatchList { watches: vec![] }, "WatchList"),
        ];
        for (sample, expected) in samples {
            let summary = bitcoin_response_summary(&sample);
            assert!(!summary.contains(XPUB), "{summary}");
            assert_eq!(summary, expected);
        }
    }

    /// **The harvest summaries print only a name and an id.** Exact, for the
    /// variants that carry secrets, for the same reason as the Bitcoin test.
    #[test]
    fn a_harvest_response_summary_prints_only_its_name_and_id() {
        use harvest_common::{BackupString, ConversationKey, HarvestDelegateResponse as R};
        let key = [0xA7u8; 32];
        let samples = [
            (
                R::ConversationKeys {
                    request_id: 42,
                    ghostkey_fingerprint: "fp-one".into(),
                    result: Ok(vec![ConversationKey {
                        peer_public_key: vec![1u8; 32],
                        buyer_to_seller: key,
                        seller_to_buyer: key,
                    }]),
                },
                "ConversationKeys (request 42, fp-one)",
            ),
            (
                R::BuyerConversationExported {
                    request_id: 42,
                    store_contract_id: vec![3u8; 32],
                    buyer_public_key: [1u8; 32],
                    result: Ok(BackupString("SECRET-BACKUP".into())),
                },
                "BuyerConversationExported (request 42)",
            ),
            (
                R::BuyerConversationList {
                    request_id: 42,
                    store_contract_id: vec![3u8; 32],
                    conversations: vec![],
                },
                "BuyerConversationList (request 42)",
            ),
            (
                R::ContractState {
                    contract_key: vec![3u8; 32],
                    state: vec![0xA7u8; 32],
                },
                "ContractState",
            ),
        ];
        for (sample, expected) in samples {
            let summary = harvest_response_summary(&sample);
            assert!(!leaks(&summary, "SECRET"), "{summary}");
            assert_eq!(summary, expected);
        }
    }

    /// An undecodable payload is described by its variant name and length,
    /// never by what serde would have quoted from it.
    #[test]
    fn an_undecodable_payload_is_described_without_its_contents() {
        #[derive(serde::Serialize)]
        enum FromTheFuture {
            BackupV9 { backup: String },
        }
        let payload = harvest_common::to_cbor(&FromTheFuture::BackupV9 {
            backup: "SECRET-BACKUP".into(),
        })
        .expect("cbor");
        let shape = payload_shape(&payload);
        assert_eq!(
            shape,
            format!("variant `BackupV9`, {} bytes", payload.len())
        );
        assert_eq!(payload_shape(&[0xff, 0x00]), "2 bytes");
    }
}
