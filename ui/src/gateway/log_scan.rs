//! The call-site guard for harvest#94 (test-only).
//!
//! #94 was a call site: `info!("... {:?}", r)` on a whole delegate response.
//! Redacting the types does not stop the next one, because several of them
//! (`GhostkeyResponse`, freenet-stdlib's `HostResponse`) derive `Debug` in
//! crates Harvest cannot change. So this reads every UI source file and
//! holds the formatting call sites to a rule.
//!
//! # What is covered
//!
//! Real code only: comments are blanked, `#[cfg(test)] mod name { .. }`
//! blocks are blanked, and files declared as `#[cfg(test)] mod name;` are
//! skipped. In what remains:
//!
//! * **Format macros** -- `info!`, `warn!`, `error!`, `debug!`, `trace!`,
//!   `println!`, `eprintln!`, `print!`, `eprint!`, `format!`,
//!   `format_args!`, `write!`, `writeln!`, `panic!`, `unreachable!`,
//!   `todo!`, `unimplemented!`, `assert!`, `assert_eq!`, `assert_ne!` and
//!   the `debug_assert` forms. Every `{:?}` / `{:#?}` argument must be in
//!   [`VETTED`] for that file. Scanning `format!` is what catches a `{:?}`
//!   laundered through a string (`let s = format!("{:?}", r); info!("{s}")`)
//!   or through a helper that wraps `format!`: it is flagged where it is
//!   formatted.
//! * **Fail closed.** A format macro whose format-string argument is not a
//!   plain `"..."` literal is flagged whatever it contains: a `target:`, a
//!   tracing field (`x = ?r`, `?r`, `%r`), a raw string, a variable. So is
//!   one invoked with `{}` or `[]`, any `?`/`%` field sigil after the format
//!   string, and any `dbg!`, `event!` or `span!`-family call.
//! * **`web_sys` console** -- any `console::...(` call is flagged; route it
//!   through a log macro instead.
//! * **Named secrets** -- in a macro that OUTPUTS (the log, print and panic
//!   families, not `format!`), any interpolated expression, Display or Debug,
//!   whose text contains a name in [`SECRET_NAMES`], e.g. the websocket URL
//!   that carries `authToken=`.
//!
//! # What is NOT covered
//!
//! It is a text scanner, and a text scanner is a moving target: a macro it
//! does not know, a `Debug` reached through a trait object, a value logged
//! via `Display` whose `Display` prints a secret. The vetting is by
//! expression text, not type (see [`VETTED`]). The structural fix is types
//! the UI cannot `Debug`-format at all; see harvest#97.
//!
//! A scrape can match itself. This file is declared `#[cfg(test)] mod
//! log_scan;`, which is exactly what makes the scan skip it.

use std::path::{Path, PathBuf};

/// One `{:?}` argument that has been looked at and judged unable to hold a
/// secret.
///
/// **Vetting is by the expression's TEXT in one file, not by its type.** The
/// scanner cannot see types, so an entry says "in this file, `key` is a
/// contract key"; if someone later binds a response to a variable called
/// `key` in that file, the entry would wrongly cover it. Scoping entries to a
/// file makes that less likely, and `ty` records what the entry assumes so a
/// reader can check it. Keep entries few.
struct Vetted {
    /// Path under `ui/src`.
    file: &'static str,
    /// The expression, whitespace removed.
    expr: &'static str,
    /// The type the entry assumes the expression has.
    ty: &'static str,
    why: &'static str,
}

const PUBLIC_ID: &str = "a public contract or delegate address";
const ID_PREFIX: &str = "the first 8 bytes of a public contract id";

const VETTED: &[Vetted] = &[
    Vetted {
        file: "components/app.rs",
        expr: "key",
        ty: "freenet_stdlib::prelude::DelegateKey",
        why: PUBLIC_ID,
    },
    Vetted {
        file: "gateway/delegate_api.rs",
        expr: "key",
        ty: "freenet_stdlib::prelude::DelegateKey",
        why: PUBLIC_ID,
    },
    Vetted {
        file: "gateway/delegate_api.rs",
        expr: "contract_key",
        ty: "freenet_stdlib::prelude::ContractKey",
        why: PUBLIC_ID,
    },
    Vetted {
        file: "gateway/response_handler.rs",
        expr: "key",
        ty: "freenet_stdlib::prelude::ContractKey",
        why: PUBLIC_ID,
    },
    Vetted {
        file: "gateway/response_handler.rs",
        expr: "sender",
        ty: "response_handler::DelegateSender",
        why: "which delegate sent a message: a fieldless enum",
    },
    Vetted {
        file: "gateway/store_ops.rs",
        expr: "reputation_id",
        ty: "freenet_stdlib::prelude::ContractInstanceId",
        why: PUBLIC_ID,
    },
    Vetted {
        file: "gateway/store_ops.rs",
        expr: "store_id",
        ty: "freenet_stdlib::prelude::ContractInstanceId",
        why: PUBLIC_ID,
    },
    Vetted {
        file: "gateway/store_ops.rs",
        expr: "mailbox_id",
        ty: "freenet_stdlib::prelude::ContractInstanceId",
        why: PUBLIC_ID,
    },
    Vetted {
        file: "gateway/bitcoin_generation_ops.rs",
        expr: "artifact",
        ty: "bitcoin_generation::Resolve",
        why: "which bridge artifact: a fieldless enum",
    },
    Vetted {
        file: "gateway/bitcoin_generation_ops.rs",
        expr: "network",
        ty: "freenet_bitcoin_common::BitcoinNetwork",
        why: "a fieldless enum",
    },
    Vetted {
        file: "state.rs",
        expr: "network",
        ty: "freenet_bitcoin_common::BitcoinNetwork",
        why: "a fieldless enum -- which chain a refused-because-behind tip \
              belonged to (harvest#74)",
    },
    Vetted {
        file: "gateway/bitcoin_generation_ops.rs",
        expr: "why",
        ty: "bitcoin_generation::Unresolved",
        why: "fieldless lookup failures plus `Refused`, a reason about a PUBLIC \
              pointer record",
    },
    Vetted {
        file: "state.rs",
        expr: "&contract_id[..8.min(contract_id.len())]",
        ty: "&[u8]",
        why: ID_PREFIX,
    },
    Vetted {
        file: "state.rs",
        expr: "&store_contract_id[..8.min(store_contract_id.len())]",
        ty: "&[u8]",
        why: ID_PREFIX,
    },
    Vetted {
        file: "state.rs",
        expr: "&edit.store_contract_id[..8.min(edit.store_contract_id.len())]",
        ty: "&[u8]",
        why: ID_PREFIX,
    },
    Vetted {
        file: "state.rs",
        expr: "status",
        ty: "harvest_common::payment::OrderStatus",
        why: "an order's lifecycle state: a fieldless enum",
    },
    Vetted {
        file: "migrate.rs",
        expr: "harvest_common::mailbox::SIZE_CLASS_CAPS",
        ty: "[usize; 4]",
        why: "a compile-time constant",
    },
];

/// Name fragments that must never be interpolated into an output macro,
/// by Display or Debug. Lower-case; matched against the expression's text.
const SECRET_NAMES: &[&str] = &[
    "token",
    "secret",
    "password",
    "signing_key",
    "xpub",
    "backup",
    // `connection.rs`: carries `?authToken=` for a node that requires one.
    "websocket_url",
];

/// What the scanner found at one call site.
#[derive(Debug, PartialEq, Eq)]
enum Finding {
    /// A `{:?}` / `{:#?}` of this expression (whitespace removed).
    Debug(String),
    /// An expression in [`SECRET_NAMES`], interpolated into output.
    Named(String),
    /// A call shape the scanner will not reason about, so refuses.
    Shape(String),
}

/// Where the format string sits in a macro's arguments, if it has one.
#[derive(Clone, Copy)]
enum Kind {
    /// Format string at this index; `output` = the result is emitted, not
    /// just built.
    Format { at: usize, output: bool },
    /// Refused outright.
    Refuse,
}

const MACROS: &[(&str, Kind)] = &[
    (
        "info",
        Kind::Format {
            at: 0,
            output: true,
        },
    ),
    (
        "warn",
        Kind::Format {
            at: 0,
            output: true,
        },
    ),
    (
        "error",
        Kind::Format {
            at: 0,
            output: true,
        },
    ),
    (
        "debug",
        Kind::Format {
            at: 0,
            output: true,
        },
    ),
    (
        "trace",
        Kind::Format {
            at: 0,
            output: true,
        },
    ),
    (
        "println",
        Kind::Format {
            at: 0,
            output: true,
        },
    ),
    (
        "eprintln",
        Kind::Format {
            at: 0,
            output: true,
        },
    ),
    (
        "print",
        Kind::Format {
            at: 0,
            output: true,
        },
    ),
    (
        "eprint",
        Kind::Format {
            at: 0,
            output: true,
        },
    ),
    (
        "panic",
        Kind::Format {
            at: 0,
            output: true,
        },
    ),
    (
        "unreachable",
        Kind::Format {
            at: 0,
            output: true,
        },
    ),
    (
        "todo",
        Kind::Format {
            at: 0,
            output: true,
        },
    ),
    (
        "unimplemented",
        Kind::Format {
            at: 0,
            output: true,
        },
    ),
    (
        "assert",
        Kind::Format {
            at: 1,
            output: true,
        },
    ),
    (
        "debug_assert",
        Kind::Format {
            at: 1,
            output: true,
        },
    ),
    (
        "assert_eq",
        Kind::Format {
            at: 2,
            output: true,
        },
    ),
    (
        "assert_ne",
        Kind::Format {
            at: 2,
            output: true,
        },
    ),
    (
        "debug_assert_eq",
        Kind::Format {
            at: 2,
            output: true,
        },
    ),
    (
        "debug_assert_ne",
        Kind::Format {
            at: 2,
            output: true,
        },
    ),
    (
        "format",
        Kind::Format {
            at: 0,
            output: false,
        },
    ),
    (
        "format_args",
        Kind::Format {
            at: 0,
            output: false,
        },
    ),
    (
        "write",
        Kind::Format {
            at: 1,
            output: false,
        },
    ),
    (
        "writeln",
        Kind::Format {
            at: 1,
            output: false,
        },
    ),
    ("dbg", Kind::Refuse),
    ("event", Kind::Refuse),
    ("span", Kind::Refuse),
    ("info_span", Kind::Refuse),
    ("warn_span", Kind::Refuse),
    ("error_span", Kind::Refuse),
    ("debug_span", Kind::Refuse),
    ("trace_span", Kind::Refuse),
];

// === Lexing ===============================================================

fn is_ident(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// The char starting at byte `i` (which must be a boundary).
fn char_at(s: &str, i: usize) -> Option<char> {
    s.get(i..).and_then(|r| r.chars().next())
}

/// Byte index of the char after the one at `i`.
fn next_char(s: &str, i: usize) -> usize {
    i + char_at(s, i).map_or(1, char::len_utf8)
}

/// If a string or char literal starts at byte `i`, the index just past it.
/// Handles `"..."`, `b"..."` (via the `"`), raw `r"..."` / `r#"..."#`, and
/// char literals of any width (`'x'`, `'é'`, `'\n'`, `'\u{..}'`); a quote
/// that opens none of those is a lifetime.
fn skip_literal(s: &str, i: usize) -> Option<usize> {
    let b = s.as_bytes();
    match b.get(i)? {
        b'"' => {
            let mut j = i + 1;
            while j < b.len() && b[j] != b'"' {
                j += if b[j] == b'\\' { 2 } else { 1 };
            }
            Some((j + 1).min(b.len()))
        }
        b'r' if matches!(b.get(i + 1), Some(b'"' | b'#'))
            && (i == 0 || !char_before(s, i).is_some_and(is_ident)) =>
        {
            let hashes = b[i + 1..].iter().take_while(|c| **c == b'#').count();
            if b.get(i + 1 + hashes) != Some(&b'"') {
                return None;
            }
            let close: Vec<u8> = std::iter::once(b'"')
                .chain(std::iter::repeat_n(b'#', hashes))
                .collect();
            let body = i + 2 + hashes;
            Some(
                b.get(body..)?
                    .windows(close.len())
                    .position(|w| w == close.as_slice())
                    .map_or(b.len(), |p| body + p + close.len()),
            )
        }
        b'\'' => {
            let first = char_at(s, i + 1)?;
            if first == '\\' {
                let close = s.get(i + 2..)?.find('\'')?;
                Some(i + 2 + close + 1)
            } else {
                let after = i + 1 + first.len_utf8();
                (b.get(after) == Some(&b'\'')).then_some(after + 1)
            }
        }
        _ => None,
    }
}

fn char_before(s: &str, i: usize) -> Option<char> {
    s.get(..i).and_then(|r| r.chars().next_back())
}

/// `src` with comments blanked (newlines kept, so line numbers hold).
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
            let end = skip_literal(src, i).unwrap_or_else(|| next_char(src, i));
            out.push_str(&src[i..end]);
            i = end;
        }
    }
    out
}

/// Index just past the bracket matching the one at `open`, skipping
/// literals; the end of `s` if it never closes.
fn matching(s: &str, open: usize) -> usize {
    let mut depth = 0i32;
    let mut i = open;
    while i < s.len() {
        if let Some(end) = skip_literal(s, i) {
            i = end;
            continue;
        }
        match s.as_bytes()[i] {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => {
                depth -= 1;
                if depth == 0 {
                    return i + 1;
                }
            }
            _ => {}
        }
        i = next_char(s, i);
    }
    s.len()
}

/// `src` with every `#[cfg(test)] mod name { .. }` blanked, and the names of
/// `#[cfg(test)] mod name;` file modules it declares.
fn strip_test_modules(src: &str) -> (String, Vec<String>) {
    let mut out = src.to_string();
    let mut file_modules = Vec::new();
    let mut from = 0;
    while let Some(at) = out[from..].find("#[cfg(test)]").map(|p| p + from) {
        let rest = &out[at + "#[cfg(test)]".len()..];
        let trimmed = rest.trim_start();
        let start = out.len() - trimmed.len();
        let decl = trimmed
            .strip_prefix("pub(crate) mod ")
            .or_else(|| trimmed.strip_prefix("pub mod "))
            .or_else(|| trimmed.strip_prefix("mod "));
        if let Some(decl) = decl {
            if let Some(end) = decl.find(['{', ';']) {
                let name = decl[..end].trim().to_string();
                if decl.as_bytes()[end] == b';' {
                    file_modules.push(name);
                } else {
                    let brace = start + (trimmed.len() - decl.len()) + end;
                    let close = matching(&out, brace);
                    let blank: String = out[at..close]
                        .chars()
                        .map(|c| if c == '\n' { '\n' } else { ' ' })
                        .collect();
                    out.replace_range(at..close, &blank);
                }
            }
        }
        from = at + 1;
    }
    (out, file_modules)
}

/// Top-level comma split of a macro's argument list.
fn split_args(args: &str) -> Vec<String> {
    let b = args.as_bytes();
    let mut parts = Vec::new();
    let (mut depth, mut start, mut i) = (0i32, 0, 0);
    while i < b.len() {
        if let Some(end) = skip_literal(args, i) {
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
        i = next_char(args, i);
    }
    let last = args[start..].trim();
    if !last.is_empty() {
        parts.push(last.to_string());
    }
    parts
}

fn squash(s: &str) -> String {
    s.chars().filter(|c| !c.is_whitespace()).collect()
}

/// A plain `"..."` literal and nothing else.
fn plain_literal(arg: &str) -> Option<&str> {
    let inner = arg.strip_prefix('"')?.strip_suffix('"')?;
    // One literal, not `"a" "b"` or `"a".to_string()`.
    (skip_literal(arg, 0) == Some(arg.len())).then_some(inner)
}

/// The findings for one format-macro call. `args` is the text between its
/// brackets.
fn check_format_call(name: &str, args: &str, at: usize, output: bool) -> Vec<Finding> {
    let parts = split_args(args);
    let Some(fmt_arg) = parts.get(at) else {
        // `panic!()`, `writeln!(f)`, `assert!(x)`: nothing is formatted.
        return Vec::new();
    };
    let Some(fmt) = plain_literal(fmt_arg) else {
        return vec![Finding::Shape(format!(
            "{name}! whose format argument is not a plain string literal: {}",
            squash(fmt_arg)
        ))];
    };
    let rest = &parts[at + 1..];
    let mut found = Vec::new();
    for arg in rest {
        let lhs_rhs = arg.split_once('=').filter(|(_, r)| !r.starts_with('='));
        let value = lhs_rhs.map_or(arg.as_str(), |(_, r)| r).trim_start();
        if value.starts_with('?') || value.starts_with('%') {
            found.push(Finding::Shape(format!(
                "{name}! with a tracing field sigil: {}",
                squash(arg)
            )));
        }
    }
    let named = |name: &str| {
        rest.iter()
            .find_map(|a| {
                let (lhs, rhs) = a.split_once('=')?;
                (lhs.trim() == name && !rhs.starts_with('=')).then(|| rhs.to_string())
            })
            .unwrap_or_else(|| name.to_string())
    };
    let mut next = 0usize;
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
        let expr = squash(&expr.unwrap_or_default());
        if output {
            let lower = expr.to_lowercase();
            if SECRET_NAMES.iter().any(|n| lower.contains(n)) {
                found.push(Finding::Named(expr.clone()));
            }
        }
        if spec.contains('?') {
            found.push(Finding::Debug(expr));
        }
    }
    found
}

/// Every finding in one file's source, as `(line, finding)`.
fn scan(src: &str) -> Vec<(usize, Finding)> {
    let (code, _) = strip_test_modules(&strip_comments(src));
    let b = code.as_bytes();
    let line_of = |i: usize| code[..i].matches('\n').count() + 1;
    let mut found = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if let Some(end) = skip_literal(&code, i) {
            i = end;
            continue;
        }
        let at_word = !char_before(&code, i).is_some_and(is_ident);
        if at_word && code[i..].starts_with("console::") {
            let path_end = i + code[i..]
                .find(|c: char| !(is_ident(c) || c == ':'))
                .unwrap_or(code.len() - i);
            if code[path_end..].trim_start().starts_with('(') {
                found.push((
                    line_of(i),
                    Finding::Shape(format!("web_sys console call {}", &code[i..path_end])),
                ));
                i = path_end;
                continue;
            }
        }
        let word_end = i + code[i..]
            .find(|c: char| !is_ident(c))
            .unwrap_or(code.len() - i);
        if at_word && word_end > i {
            let word = &code[i..word_end];
            let after = code[word_end..].trim_start();
            if let (Some(&(_, kind)), true) = (
                MACROS.iter().find(|(m, _)| *m == word),
                after.starts_with('!') && !after.starts_with("!="),
            ) {
                let bang = code.len() - after.len();
                let open_rest = code[bang + 1..].trim_start();
                let open = code.len() - open_rest.len();
                let bracket = open_rest.as_bytes().first().copied();
                if matches!(bracket, Some(b'(' | b'[' | b'{')) {
                    let close = matching(&code, open);
                    let inner = &code[open + 1..close.saturating_sub(1).max(open + 1)];
                    let line = line_of(i);
                    match (kind, bracket) {
                        (Kind::Refuse, _) => {
                            found.push((line, Finding::Shape(format!("{word}! is not allowed"))))
                        }
                        (Kind::Format { .. }, Some(b'[' | b'{')) => found.push((
                            line,
                            Finding::Shape(format!("{word}! invoked with brackets or braces")),
                        )),
                        (Kind::Format { at, output }, _) => {
                            for f in check_format_call(word, inner, at, output) {
                                found.push((line, f));
                            }
                        }
                    }
                    // Continue INSIDE the arguments, not past them: a
                    // `format!("{r:?}")` nested in them is a call site of its
                    // own. The outer macro's findings come only from its own
                    // format string, above.
                    i = open + 1;
                    continue;
                }
            }
            i = word_end;
            continue;
        }
        i = next_char(&code, i);
    }
    found
}

/// [`scan`], turning any internal failure into a message naming the file,
/// rather than a panic from deep inside the lexer.
fn scan_file(path: &Path, src: &str) -> Vec<(usize, Finding)> {
    scan_file_with(path, src, scan)
}

fn scan_file_with(
    path: &Path,
    src: &str,
    scanner: fn(&str) -> Vec<(usize, Finding)>,
) -> Vec<(usize, Finding)> {
    std::panic::catch_unwind(|| scanner(src)).unwrap_or_else(|cause| {
        let why = cause
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| cause.downcast_ref::<&str>().map(|s| s.to_string()))
            .unwrap_or_default();
        panic!("log scanner could not parse {}: {why}", path.display())
    })
}

fn src_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

/// Every `.rs` file under `ui/src` except those declared as
/// `#[cfg(test)] mod name;`.
fn ui_sources() -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("read ui/src") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }
    let mut all = Vec::new();
    walk(&src_dir(), &mut all);
    let mut test_only = Vec::new();
    for path in &all {
        let src = std::fs::read_to_string(path).expect("read source");
        let (_, modules) = strip_test_modules(&strip_comments(&src));
        // `a.rs` declares `a/name.rs`; `mod.rs` and `main.rs` declare
        // siblings.
        let dir = match path.file_stem().and_then(|s| s.to_str()) {
            Some("mod" | "main" | "lib") => path.parent().map(Path::to_path_buf),
            Some(stem) => path.parent().map(|p| p.join(stem)),
            None => None,
        };
        for name in modules {
            if let Some(dir) = &dir {
                test_only.push(dir.join(format!("{name}.rs")));
                test_only.push(dir.join(&name).join("mod.rs"));
            }
        }
    }
    all.retain(|p| !test_only.contains(p));
    all
}

/// **No formatting call site in the UI formats a value nobody has vetted,
/// interpolates a named secret, or takes a shape the scanner refuses**
/// (harvest#94, reviews of #96).
#[test]
fn no_call_site_formats_an_unvetted_value() {
    let mut problems = Vec::new();
    let mut debug_args = 0;
    let mut used = vec![false; VETTED.len()];
    for path in ui_sources() {
        let src = std::fs::read_to_string(&path).expect("read source");
        let rel = path
            .strip_prefix(src_dir())
            .expect("under src")
            .to_string_lossy()
            .replace('\\', "/");
        for (line, finding) in scan_file(&path, &src) {
            match &finding {
                Finding::Debug(expr) => {
                    debug_args += 1;
                    match VETTED
                        .iter()
                        .position(|v| v.file == rel && v.expr == expr.as_str())
                    {
                        Some(index) => used[index] = true,
                        None => problems.push(format!("{rel}:{line}: {{:?}} of `{expr}`")),
                    }
                }
                Finding::Named(expr) => {
                    problems.push(format!("{rel}:{line}: interpolates `{expr}`"))
                }
                Finding::Shape(what) => problems.push(format!("{rel}:{line}: {what}")),
            }
        }
    }
    // Far fewer than today means the scan stopped finding call sites, not
    // that they went away.
    assert!(
        debug_args >= 15,
        "only {debug_args} `{{:?}}` arguments found"
    );
    assert!(
        problems.is_empty(),
        "formatting call sites the harvest#94 guard does not accept -- log a \
         summary from `gateway::log_summary` instead, or, for a value that can \
         never hold a secret, add a `Vetted` entry stating its type and why:\n{}",
        problems.join("\n")
    );
    let stale: Vec<String> = VETTED
        .iter()
        .zip(&used)
        .filter(|(_, used)| !**used)
        .map(|(v, _)| format!("{}: `{}` ({}; {})", v.file, v.expr, v.ty, v.why))
        .collect();
    assert!(
        stale.is_empty(),
        "vetted entries nothing uses any more; remove them:\n{}",
        stale.join("\n")
    );
}

/// The scanner itself, one shape at a time: each fixture's findings, exactly.
#[test]
fn the_scanner_sees_every_shape() {
    use Finding::{Debug as D, Named as N, Shape as S};
    let shape = |s: &str| S(s.to_string());
    let cases: Vec<(&str, Vec<Finding>)> = vec![
        // Positional, inline, named, pretty.
        (r#"info!("x {:?}", r);"#, vec![D("r".into())]),
        (
            r#"dioxus::logger::tracing::info!("x {other:?}");"#,
            vec![D("other".into())],
        ),
        (
            r#"warn!("{x:#?} and {}", y, x = response);"#,
            vec![D("response".into())],
        ),
        (
            r#"error!("{} then {:?}", key, whole);"#,
            vec![D("whole".into())],
        ),
        (r#"error!("{1:?} {0}", a, b);"#, vec![D("b".into())]),
        // Laundering: caught where it is formatted.
        (
            r#"let s = format!("{:?}", r); info!("{}", s);"#,
            vec![D("r".into())],
        ),
        (
            r#"fn describe(r: &R) -> String { format!("{r:?}") }"#,
            vec![D("r".into())],
        ),
        (r#"let a = format_args!("{:?}", r);"#, vec![D("r".into())]),
        // Nested inside another macro's arguments.
        (r#"info!("{}", format!("{:?}", r));"#, vec![D("r".into())]),
        (
            r#"info!("{}", format_args!("{:?}", r));"#,
            vec![D("r".into())],
        ),
        (r#"write!(f, "{:?}", r)?;"#, vec![D("r".into())]),
        (
            r#"writeln!(f, "{:?}", r)?; writeln!(f)?;"#,
            vec![D("r".into())],
        ),
        (r#"panic!("{:?}", r);"#, vec![D("r".into())]),
        (r#"unreachable!("{:?}", r);"#, vec![D("r".into())]),
        (
            r#"assert!(ok, "{:?}", r); assert!(ok);"#,
            vec![D("r".into())],
        ),
        (r#"assert_eq!(a, b, "{:?}", r);"#, vec![D("r".into())]),
        (r#"debug_assert_ne!(a, b, "{r:?}");"#, vec![D("r".into())]),
        // Fail closed.
        (
            r#"info!(target: "x", "{}", t);"#,
            vec![shape(
                "info! whose format argument is not a plain string literal: target:\"x\"",
            )],
        ),
        (
            r#"info!(x = ?r, "m");"#,
            vec![shape(
                "info! whose format argument is not a plain string literal: x=?r",
            )],
        ),
        (
            r#"info!(?r, "m");"#,
            vec![shape(
                "info! whose format argument is not a plain string literal: ?r",
            )],
        ),
        (
            r#"info!(%r);"#,
            vec![shape(
                "info! whose format argument is not a plain string literal: %r",
            )],
        ),
        (
            r#"info!("m {}", a, x = ?r);"#,
            vec![shape("info! with a tracing field sigil: x=?r")],
        ),
        (
            r##"info!(r#"{:?}"#, raw);"##,
            vec![shape(
                "info! whose format argument is not a plain string literal: r#\"{:?}\"#",
            )],
        ),
        (
            r#"info!(msg, r);"#,
            vec![shape(
                "info! whose format argument is not a plain string literal: msg",
            )],
        ),
        (
            r#"info!{"{:?}", r};"#,
            vec![shape("info! invoked with brackets or braces")],
        ),
        (
            r#"tracing::event!(Level::INFO, "{:?}", r);"#,
            vec![shape("event! is not allowed")],
        ),
        (r#"let x = dbg!(r);"#, vec![shape("dbg! is not allowed")]),
        (
            r#"web_sys::console::log_1(&r.into());"#,
            vec![shape("web_sys console call console::log_1")],
        ),
        // Named secrets, by Display too; not in `format!`, which builds.
        (
            r#"info!("at {}", websocket_url);"#,
            vec![N("websocket_url".into())],
        ),
        (r#"error!("{auth_token}");"#, vec![N("auth_token".into())]),
        (
            r#"let u = format!("{}?authToken={}", base, token);"#,
            vec![],
        ),
        // Not findings.
        (r#"info!("fine {} {}", a, b); if x != y {}"#, vec![]),
        (r#"// info!("{:?}", commented);"#, vec![]),
        (
            r#"let u = "http://x"; info!("after {:?}", after_url);"#,
            vec![D("after_url".into())],
        ),
        (
            "#[cfg(test)]\nmod tests {\n    fn t() { info!(\"{:?}\", in_test); }\n}\n",
            vec![],
        ),
        (r#"info!("{{:?}} is literal");"#, vec![]),
        // Non-ASCII outside strings must not throw the lexer off.
        (
            r#"let c = 'é'; let e = '—'; let d = '\u{e9}'; fn f<'a>(x: &'a str) {} info!("{:?}", r);"#,
            vec![D("r".into())],
        ),
    ];
    for (src, expected) in cases {
        let found: Vec<Finding> = scan(src).into_iter().map(|(_, f)| f).collect();
        assert_eq!(found, expected, "scanning: {src}");
    }
}

/// An internal scanner failure names the file.
#[test]
#[should_panic(expected = "log scanner could not parse /nowhere.rs: boom")]
fn a_scanner_failure_names_the_file() {
    fn broken(_: &str) -> Vec<(usize, Finding)> {
        panic!("boom")
    }
    let _ = scan_file_with(Path::new("/nowhere.rs"), "", broken);
}
