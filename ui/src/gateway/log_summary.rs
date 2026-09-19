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
//! concerns, and nothing else. `no_log_line_debug_formats_an_unvetted_value`
//! below holds every log call in the UI to that.
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
        R::ReputationKeysInitialized {
            ghostkey_fingerprint,
            ..
        } => (
            "ReputationKeysInitialized",
            Some(ghostkey_fingerprint.clone()),
        ),
        R::RsaPublicKey {
            ghostkey_fingerprint,
            ..
        } => ("RsaPublicKey", Some(ghostkey_fingerprint.clone())),
        R::EncryptionKeyReady {
            ghostkey_fingerprint,
            ..
        } => ("EncryptionKeyReady", Some(ghostkey_fingerprint.clone())),
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
        R::BlindSignatureResult { request_id, .. } => ("BlindSignatureResult", request(request_id)),
        R::ListingCreated { request_id, .. } => ("ListingCreated", request(request_id)),
        R::TransactionRecorded { request_id, .. } => ("TransactionRecorded", request(request_id)),
        R::BlindSignatureRecorded { request_id, .. } => {
            ("BlindSignatureRecorded", request(request_id))
        }
        R::TransactionList { .. } => ("TransactionList", None),
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

    // === The call sites ===================================================
    //
    // The summaries above only help if the log lines use them: #94 itself was
    // a call site formatting a whole response with `{:?}`. What follows reads
    // every UI source file and holds each log macro's `{:?}` / `{:#?}`
    // arguments to a short list of vetted expressions -- keys, ids and small
    // enums -- so reverting any call site to `{:?}` of a response fails here.
    //
    // It is a source scrape, and a source scrape can match itself: this
    // file's own tests and the allow-list below are full of `{:?}` and
    // macro names. So comments and `#[cfg(test)] mod` blocks are stripped
    // before anything is matched, and `tests.rs` files are skipped (they are
    // `#[cfg(test)] mod tests;` targets). What is scanned is real code only.

    /// Every expression the UI's log lines may format with `{:?}`, whitespace
    /// removed, with why it is safe. Add to this only for a value that cannot
    /// hold a secret now or after a plausible change to its type.
    const VETTED_DEBUG_ARGS: &[&str] = &[
        // Contract / delegate keys and instance ids: public addresses.
        "key",
        "contract_key",
        "reputation_id",
        "store_id",
        "mailbox_id",
        // The first 8 bytes of a public contract id.
        "&contract_id[..8.min(contract_id.len())]",
        "&store_contract_id[..8.min(store_contract_id.len())]",
        "&edit.store_contract_id[..8.min(edit.store_contract_id.len())]",
        // Which bridge artifact / Bitcoin network: fieldless enums.
        "artifact",
        "network",
        // Why a bridge generation pointer did not resolve
        // (`bitcoin_generation::Unresolved`): fieldless lookup failures plus
        // `Refused`, a reason about a PUBLIC pointer record.
        "why",
        // Which delegate a message came from: a fieldless enum.
        "sender",
    ];

    /// `src` with comments blanked (newlines kept, so line numbers hold).
    /// Strings and char literals are recognised so a `//` inside one is not
    /// taken for a comment.
    fn strip_comments(src: &str) -> String {
        let b = src.as_bytes();
        let mut out = String::with_capacity(src.len());
        let mut i = 0;
        while i < b.len() {
            if b[i..].starts_with(b"//") {
                while i < b.len() && b[i] != b'\n' {
                    i += 1;
                }
            } else if b[i..].starts_with(b"/*") {
                let mut depth = 0;
                while i < b.len() {
                    if b[i..].starts_with(b"/*") {
                        depth += 1;
                        i += 2;
                    } else if b[i..].starts_with(b"*/") {
                        depth -= 1;
                        i += 2;
                        if depth == 0 {
                            break;
                        }
                    } else {
                        if b[i] == b'\n' {
                            out.push('\n');
                        }
                        i += 1;
                    }
                }
            } else {
                let end = skip_literal(b, i).unwrap_or(i + 1);
                out.push_str(&src[i..end]);
                i = end;
            }
        }
        out
    }

    /// If a string or char literal starts at `i`, the index just past it.
    fn skip_literal(b: &[u8], i: usize) -> Option<usize> {
        match b[i] {
            b'"' => {
                let mut j = i + 1;
                while j < b.len() && b[j] != b'"' {
                    j += if b[j] == b'\\' { 2 } else { 1 };
                }
                Some(j + 1)
            }
            b'r' if b.get(i + 1) == Some(&b'"') || b.get(i + 1) == Some(&b'#') => {
                let hashes = b[i + 1..].iter().take_while(|c| **c == b'#').count();
                if b.get(i + 1 + hashes) != Some(&b'"') {
                    return None;
                }
                let close: Vec<u8> = std::iter::once(b'"')
                    .chain(std::iter::repeat_n(b'#', hashes))
                    .collect();
                let body = i + 2 + hashes;
                b[body..]
                    .windows(close.len())
                    .position(|w| w == close.as_slice())
                    .map(|p| body + p + close.len())
            }
            // A char literal, not a lifetime: `'x'` or `'\..'`.
            b'\'' if b.get(i + 2) == Some(&b'\'') || b.get(i + 1) == Some(&b'\\') => {
                let mut j = i + 1;
                while j < b.len() && b[j] != b'\'' {
                    j += if b[j] == b'\\' { 2 } else { 1 };
                }
                Some(j + 1)
            }
            _ => None,
        }
    }

    /// Index just past the bracket matching the one at `open`, skipping
    /// literals.
    fn matching(b: &[u8], open: usize) -> usize {
        let mut depth = 0i32;
        let mut i = open;
        while i < b.len() {
            if let Some(end) = skip_literal(b, i) {
                i = end;
                continue;
            }
            match b[i] {
                b'(' | b'[' | b'{' => depth += 1,
                b')' | b']' | b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        return i + 1;
                    }
                }
                _ => {}
            }
            i += 1;
        }
        b.len()
    }

    /// `src` with every `#[cfg(test)] mod name { .. }` blanked.
    fn strip_test_modules(src: &str) -> String {
        let mut out = src.to_string();
        let mut from = 0;
        while let Some(at) = out[from..].find("#[cfg(test)]").map(|p| p + from) {
            let rest = &out[at + "#[cfg(test)]".len()..];
            let trimmed = rest.trim_start();
            let start = out.len() - trimmed.len();
            if trimmed.starts_with("mod ") {
                if let Some(brace) = trimmed.find(['{', ';']) {
                    if trimmed.as_bytes()[brace] == b'{' {
                        let end = matching(out.as_bytes(), start + brace);
                        let blank: String = out[at..end]
                            .chars()
                            .map(|c| if c == '\n' { '\n' } else { ' ' })
                            .collect();
                        out.replace_range(at..end, &blank);
                    }
                }
            }
            from = at + 1;
        }
        out
    }

    /// Top-level comma split of a macro's argument list.
    fn split_args(args: &str) -> Vec<String> {
        let b = args.as_bytes();
        let mut parts = Vec::new();
        let (mut depth, mut start, mut i) = (0i32, 0, 0);
        while i < b.len() {
            if let Some(end) = skip_literal(b, i) {
                i = end;
                continue;
            }
            match b[i] {
                b'(' | b'[' | b'{' => depth += 1,
                b')' | b']' | b'}' => depth -= 1,
                b',' if depth == 0 => {
                    parts.push(args[start..i].trim().to_string());
                    start = i + 1;
                }
                _ => {}
            }
            i += 1;
        }
        let last = args[start..].trim();
        if !last.is_empty() {
            parts.push(last.to_string());
        }
        parts
    }

    /// The expressions a macro call formats with `{:?}` / `{:#?}`,
    /// whitespace removed. `args` is the text between the parentheses.
    fn debug_args(args: &str) -> Vec<String> {
        let parts = split_args(args);
        let Some(fmt) = parts.first().and_then(|f| f.strip_prefix('"')) else {
            return Vec::new();
        };
        let fmt = fmt.strip_suffix('"').unwrap_or(fmt);
        let rest = &parts[1..];
        let named = |name: &str| {
            rest.iter()
                .find_map(|a| {
                    let (lhs, rhs) = a.split_once('=')?;
                    (lhs.trim() == name && !rhs.starts_with('=')).then(|| rhs.to_string())
                })
                .unwrap_or_else(|| name.to_string())
        };
        let (mut found, mut next) = (Vec::new(), 0usize);
        let mut chars = fmt.char_indices().peekable();
        while let Some((i, c)) = chars.next() {
            if c != '{' {
                continue;
            }
            if chars.peek().map(|(_, c)| *c) == Some('{') {
                chars.next();
                continue;
            }
            let Some(close) = fmt[i..].find('}') else {
                break;
            };
            let inner = &fmt[i + 1..i + close];
            let (arg, spec) = inner.split_once(':').unwrap_or((inner, ""));
            let expr = if arg.is_empty() {
                next += 1;
                rest.get(next - 1).cloned()
            } else if let Ok(index) = arg.parse::<usize>() {
                rest.get(index).cloned()
            } else {
                Some(named(arg))
            };
            if spec.contains('?') {
                let expr = expr.unwrap_or_default();
                found.push(expr.chars().filter(|c| !c.is_whitespace()).collect());
            }
        }
        found
    }

    /// Every `{:?}` argument of every log macro call in real code in `src`,
    /// as `(line, expression)`.
    fn logged_debug_args(src: &str) -> Vec<(usize, String)> {
        const MACROS: &[&str] = &[
            "info", "warn", "error", "debug", "trace", "println", "eprintln", "print", "eprint",
        ];
        let code = strip_test_modules(&strip_comments(src));
        let b = code.as_bytes();
        let mut found = Vec::new();
        let mut i = 0;
        while i < b.len() {
            if let Some(end) = skip_literal(b, i) {
                i = end;
                continue;
            }
            let at_word = i == 0 || !(b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_');
            let hit = at_word
                .then(|| {
                    MACROS.iter().find(|m| {
                        code[i..].starts_with(*m)
                            && code[i + m.len()..].trim_start().starts_with('!')
                    })
                })
                .flatten();
            if let Some(m) = hit {
                let after_bang = i + m.len() + code[i + m.len()..].find('!').unwrap_or(0) + 1;
                let open =
                    after_bang + code[after_bang..].len() - code[after_bang..].trim_start().len();
                if b.get(open) == Some(&b'(') {
                    let close = matching(b, open);
                    let line = code[..i].matches('\n').count() + 1;
                    for expr in debug_args(&code[open + 1..close - 1]) {
                        found.push((line, expr));
                    }
                    i = close;
                    continue;
                }
            }
            i += 1;
        }
        found
    }

    fn ui_sources() -> Vec<std::path::PathBuf> {
        fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
            for entry in std::fs::read_dir(dir).expect("read ui/src") {
                let path = entry.expect("dir entry").path();
                if path.is_dir() {
                    walk(&path, out);
                } else if path.extension().is_some_and(|e| e == "rs")
                    && path.file_name().is_some_and(|n| n != "tests.rs")
                {
                    out.push(path);
                }
            }
        }
        let mut out = Vec::new();
        walk(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
            &mut out,
        );
        out
    }

    /// **No log line in the UI `{:?}`-formats a value that has not been
    /// vetted** (harvest#94, review of #96).
    #[test]
    fn no_log_line_debug_formats_an_unvetted_value() {
        let mut unvetted = Vec::new();
        let mut scanned = 0;
        for path in ui_sources() {
            let src = std::fs::read_to_string(&path).expect("read source");
            for (line, expr) in logged_debug_args(&src) {
                scanned += 1;
                if !VETTED_DEBUG_ARGS.contains(&expr.as_str()) {
                    unvetted.push(format!("{}:{line}: {{:?}} of `{expr}`", path.display()));
                }
            }
        }
        // The UI has a couple of dozen vetted `{:?}` log arguments. Far fewer
        // means the scan stopped finding macro calls, not that they went away.
        assert!(scanned >= 10, "only {scanned} `{{:?}}` log arguments found");
        assert!(
            unvetted.is_empty(),
            "log lines Debug-format values nobody has vetted -- log a summary \
             from `gateway::log_summary` instead, or, if the value can never \
             hold a secret, add it to VETTED_DEBUG_ARGS with why:\n{}",
            unvetted.join("\n")
        );
    }

    /// The scanner itself: it must see a `{:?}` of a response in each shape a
    /// log line can take, and must not see one in a comment or a test module.
    #[test]
    fn the_log_scan_finds_what_it_must_and_nothing_else() {
        let src = r#"
fn live(r: &R, other: &H) {
    info!("Harvest delegate response: {:?}", r);
    dioxus::logger::tracing::info!("Unhandled host response: {other:?}");
    warn!("pretty {x:#?} and {}", y, x = response);
    error!("positional {} then {:?}", key, whole);
    // info!("in a comment: {:?}", commented);
    let url = "http://example"; info!("after a url: {:?}", after_url);
}

#[cfg(test)]
mod tests {
    fn t() { info!("in a test: {:?}", in_test); }
}
"#;
        let found: Vec<String> = logged_debug_args(src).into_iter().map(|(_, e)| e).collect();
        assert_eq!(
            found,
            vec!["r", "other", "response", "whole", "after_url"],
            "the scanner's view of the fixture"
        );
    }
}
