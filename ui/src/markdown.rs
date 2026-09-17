//! A seller's own words, rendered without letting them run code.
//!
//! A store description is the one place in Harvest where one person's text is
//! shown to everyone else, so it is worth being precise about what "supports
//! markdown" may and may not mean here.
//!
//! # Why this parses to elements instead of producing HTML
//!
//! The short route is to render markdown to an HTML string and hand it to
//! `dangerous_inner_html`. That would put a `<script>` a seller typed into the
//! page, inside the app's own origin, where it can read the delegate
//! connection and every key the page can reach. Markdown allows raw HTML by
//! definition, so this is not a corner case: it is the first thing an attacker
//! would try. There is no sanitiser in this build, and adding one would mean
//! trusting it forever.
//!
//! So the parser's events become a small tree of [`Block`] and [`Inline`], and
//! the renderer builds real elements from it. Anything the tree cannot
//! represent cannot reach the page as markup: the tree has no node for raw
//! HTML, so a seller's tags arrive as literal TEXT, visible and inert.
//!
//! Text rather than dropped, because dropping it loses more than the tags. In
//! CommonMark an HTML block runs to the next blank line, and every line in it
//! arrives as raw HTML -- so a stray `<div>` at the top of a description made
//! the whole description disappear, with nothing said to the seller (who is
//! typing in a textarea with no preview) or to the buyer.
//!
//! # What is allowed, and why each limit is there
//!
//! * **Headings, demoted.** A seller's `#` becomes an `h4`, never an `h1`.
//!   The store's own name is the `h3` above, and a description that could
//!   outrank the page's own chrome is a way to impersonate it.
//! * **Links to http, https and mailto only.** `javascript:` and `data:` URLs
//!   are code, and a browser will run them from an `href`. A refused link is
//!   rendered as its own text, so nothing silently disappears.
//! * **Images are not fetched, only their alt text is shown.** An image URL
//!   is a request to a third party from every viewer's browser, which is a
//!   tracking pixel and a deanonymiser in an app whose point is pseudonymity.
//! * **Lists, emphasis, code, quotes and rules** carry no such risk and are
//!   rendered as they read.
//! * **A link whose text is a different address than its target says so.**
//!   Plain text made a URL inert; a link does not, and this is the screen
//!   where somebody decides whether to send money to a stranger.
//!
//! # Why there are caps
//!
//! A description is attacker-controlled input that every visitor renders, and
//! the renderer walks the tree recursively, as does dropping it. wasm links
//! with a 1 MiB stack and a stack overflow there is an unrecoverable trap, not
//! a catchable panic: it kills the whole app, and since the text lives in
//! contract state, reloading re-reads it and dies again. Two kilobytes of
//! `>>>>` nests fifty thousand deep, so [`MAX_DEPTH`] flattens past a depth no
//! honest description reaches, [`MAX_SOURCE_BYTES`] bounds the input, and
//! [`MAX_NODES`] bounds what one description can put in the page. Runs of text
//! are also coalesced, because the parser emits an event per unmatched
//! punctuation character and one node per byte is its own denial of service.

use dioxus::prelude::*;
use pulldown_cmark::{Event, HeadingLevel, Options, Parser, Tag, TagEnd};

/// The longest description this renders. Past it the text is cut, with a
/// marker, rather than silently shortened.
pub const MAX_SOURCE_BYTES: usize = 16 * 1024;

/// How deeply containers may nest before the rest is flattened into the
/// container that holds them. Bounds recursion in the renderer AND in the
/// tree's own `Drop`, which is why it is enforced here and not at render
/// time.
pub const MAX_DEPTH: usize = 16;

/// The most nodes one description may put in the page.
pub const MAX_NODES: usize = 4096;

/// A run of text inside a block.
#[derive(Clone, Debug, PartialEq)]
pub enum Inline {
    Text(String),
    Code(String),
    Emphasis(Vec<Inline>),
    Strong(Vec<Inline>),
    /// Only ever built with an href [`safe_href`] accepted.
    Link {
        href: String,
        children: Vec<Inline>,
    },
    Break,
}

/// One block of a description.
#[derive(Clone, Debug, PartialEq)]
pub enum Block {
    Paragraph(Vec<Inline>),
    /// `level` is already demoted; see the module doc.
    Heading {
        level: u8,
        children: Vec<Inline>,
    },
    Code(String),
    Quote(Vec<Block>),
    List {
        ordered: bool,
        items: Vec<Vec<Block>>,
    },
    Rule,
}

/// The href to use, or `None` for a scheme this will not put in an `href`.
///
/// Anything that is not plainly http, https or mailto is refused, rather than
/// listing the schemes that are dangerous: the second list is the one that is
/// missing an entry when a browser adds a scheme.
pub fn safe_href(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    // Case-insensitively, and against the scheme only: `https://x/javascript:`
    // is a perfectly good URL.
    let lowered = trimmed.to_ascii_lowercase();
    let allowed = ["http://", "https://", "mailto:"]
        .iter()
        .any(|scheme| lowered.starts_with(scheme));
    // A control character in an href is an attempt to smuggle a scheme past
    // the check above (`java\nscript:`), which browsers have historically
    // tolerated.
    let clean = !trimmed.chars().any(|c| c.is_control());
    (allowed && clean && !names_a_local_host(&lowered)).then(|| trimmed.to_string())
}

/// The host part of an http(s) URL, lowercased, without userinfo or port.
fn host_of(lowered_url: &str) -> Option<&str> {
    let after_scheme = lowered_url
        .strip_prefix("http://")
        .or_else(|| lowered_url.strip_prefix("https://"))?;
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_scheme);
    // `https://freenet.org@evil.example/` is evil.example.
    let host = authority.rsplit('@').next().unwrap_or(authority);
    // An IPv6 literal loses its brackets here, so compare against `::1`
    // rather than `[::1]`.
    let host = match host.strip_prefix('[') {
        Some(rest) => rest.split(']').next().unwrap_or(rest),
        None => host.split(':').next().unwrap_or(host),
    };
    (!host.is_empty()).then_some(host)
}

/// Whether the URL names the machine the app is running on.
///
/// A relative link is refused because it resolves inside this app's own
/// origin; an absolute one naming that same origin does exactly the same
/// thing, and a node serves its webapps from loopback. Left allowed, a seller
/// could hand a buyer a one-click load of any contract webapp at the node's
/// real origin -- a look-alike Harvest, say -- because the shell opens
/// `target="_blank"` links as real top-level tabs.
///
/// Residual, stated rather than implied: a node reached through a PUBLIC
/// hostname is not recognised here, because this function is pure and the
/// origin is only known at runtime. What it does cover is the shape every
/// local node has.
fn names_a_local_host(lowered_url: &str) -> bool {
    let Some(host) = host_of(lowered_url) else {
        return false;
    };
    if host == "localhost" || host == "0.0.0.0" {
        return true;
    }
    // IPv6 loopback, in the spellings a URL can carry.
    if host == "::1" || host == "0:0:0:0:0:0:0:1" || host == "::ffff:127.0.0.1" {
        return true;
    }
    if host.ends_with(".localhost") || host.ends_with(".local") {
        return true;
    }
    // 127/8, 10/8, 192.168/16, 172.16/12 and link-local 169.254/16.
    if host.starts_with("127.") || host.starts_with("10.") || host.starts_with("192.168.") {
        return true;
    }
    if host.starts_with("169.254.") {
        return true;
    }
    if let Some(rest) = host.strip_prefix("172.") {
        if let Some(second) = rest.split('.').next() {
            if let Ok(octet) = second.parse::<u8>() {
                return (16..=31).contains(&octet);
            }
        }
    }
    false
}

/// A note naming the real destination, when a link's TEXT claims a different
/// one.
///
/// Only when the text itself looks like an address: `[my shop](https://x)` is
/// ordinary and says nothing about where it goes, while
/// `[https://freenet.org](https://evil.example)` is a lie the reader cannot
/// see. Returns the text to append inside the link.
fn disagreeing_host_note(href: &str, children: &[Inline]) -> Option<String> {
    let text: String = children
        .iter()
        .map(|inline| match inline {
            Inline::Text(t) | Inline::Code(t) => t.as_str(),
            _ => "",
        })
        .collect();
    let claim = text.trim().to_ascii_lowercase();
    // Does the text look like an address at all?
    let looks_like_a_url = claim.contains("://") || claim.starts_with("www.");
    if !looks_like_a_url || claim.contains(char::is_whitespace) {
        return None;
    }
    let claimed = host_of(&claim).or_else(|| {
        claim
            .strip_prefix("www.")
            .and_then(|rest| rest.split(['/', '?', '#']).next())
    })?;
    let lowered_href = href.to_ascii_lowercase();
    let real = host_of(&lowered_href)?;
    // `www.` is not a different site than the bare host.
    let same = real == claimed
        || real.strip_prefix("www.") == Some(claimed)
        || claimed.strip_prefix("www.") == Some(real);
    (!same).then(|| format!(" (goes to {real})"))
}

/// What an inline container becomes when it closes.
enum InlineKind {
    Paragraph,
    /// A paragraph nobody opened. A tight list item's text arrives with no
    /// paragraph around it, and without this each run became its own
    /// paragraph, so "ships **fast**" rendered as two.
    ImplicitParagraph,
    Heading(u8),
    Emphasis,
    Strong,
    /// The href, or `None` for a link this will not make clickable.
    Link(Option<String>),
    /// Contributes its children to its parent with no wrapper, for an image's
    /// alt text and for anything unrecognised.
    Plain,
}

fn demote(level: HeadingLevel) -> u8 {
    match level {
        HeadingLevel::H1 | HeadingLevel::H2 => 4,
        HeadingLevel::H3 => 5,
        _ => 6,
    }
}

/// Accumulates the tree as the parser's events arrive.
#[derive(Default)]
struct Builder {
    /// Block containers: the document, then one per open quote or list item.
    blocks: Vec<Vec<Block>>,
    /// Lists being built, innermost last.
    lists: Vec<(bool, Vec<Vec<Block>>)>,
    /// Inline containers, innermost last, with what each becomes.
    inlines: Vec<Vec<Inline>>,
    kinds: Vec<InlineKind>,
    /// Text inside a code block, which is not markdown.
    code: Option<String>,
    /// Nodes emitted so far, against [`MAX_NODES`].
    nodes: usize,
    /// Containers refused for depth, so their `End` is refused to match.
    suppressed: usize,
    /// Set when a cap cut something, so the reader is told rather than left
    /// wondering where the rest went.
    truncated: bool,
}

impl Builder {
    fn new() -> Self {
        Builder {
            blocks: vec![Vec::new()],
            ..Builder::default()
        }
    }

    fn push_block(&mut self, block: Block) {
        self.nodes += 1;
        self.blocks
            .last_mut()
            .expect("the document container is never popped")
            .push(block);
    }

    /// Whether there is room for more, recording the cut if there is not.
    fn room(&mut self) -> bool {
        if self.nodes >= MAX_NODES {
            self.truncated = true;
            return false;
        }
        true
    }

    /// How deep the containers currently go.
    fn depth(&self) -> usize {
        // The document container is not nesting, hence the -1.
        self.blocks.len() - 1 + self.inlines.len() + self.lists.len()
    }

    fn start_inline(&mut self, kind: InlineKind) {
        // A block-level start closes an implicit paragraph: the two cannot
        // nest, and leaving it open would swallow the new block's text.
        if matches!(kind, InlineKind::Paragraph | InlineKind::Heading(_)) {
            self.flush_implicit();
        }
        // Past the cap the container is refused and its children land in
        // whatever holds it, so the text survives and the nesting does not.
        if self.depth() >= MAX_DEPTH {
            self.truncated = true;
            self.suppressed += 1;
            return;
        }
        self.inlines.push(Vec::new());
        self.kinds.push(kind);
    }

    /// Somewhere to put a run of text, opening an implicit paragraph if the
    /// parser gave us none.
    fn inline_target(&mut self) -> &mut Vec<Inline> {
        if self.inlines.is_empty() {
            self.inlines.push(Vec::new());
            self.kinds.push(InlineKind::ImplicitParagraph);
        }
        self.inlines.last_mut().expect("just ensured there is one")
    }

    fn push_inline(&mut self, inline: Inline) {
        if !self.room() {
            return;
        }
        // Coalesced, because the parser emits an event per unmatched
        // punctuation character: `"[".repeat(50_000)` is fifty thousand
        // events, and one node per byte is its own denial of service.
        let coalesced = {
            let target = self.inline_target();
            match (target.last_mut(), &inline) {
                (Some(Inline::Text(existing)), Inline::Text(added)) => {
                    existing.push_str(added);
                    true
                }
                _ => false,
            }
        };
        if !coalesced {
            self.nodes += 1;
            self.inline_target().push(inline);
        }
    }

    /// Whether this `End` belongs to a container the depth cap refused.
    fn end_was_suppressed(&mut self) -> bool {
        if self.suppressed > 0 {
            self.suppressed -= 1;
            return true;
        }
        false
    }

    /// Close the innermost inline container and put it where it belongs.
    fn end_inline(&mut self) {
        let children = self.inlines.pop().unwrap_or_default();
        let kind = self.kinds.pop();
        let finished = match kind {
            Some(InlineKind::Heading(level)) => {
                if !children.is_empty() {
                    self.push_block(Block::Heading { level, children });
                }
                return;
            }
            Some(InlineKind::Paragraph) | Some(InlineKind::ImplicitParagraph) => {
                if !children.is_empty() {
                    self.push_block(Block::Paragraph(children));
                }
                return;
            }
            Some(InlineKind::Emphasis) => vec![Inline::Emphasis(children)],
            Some(InlineKind::Strong) => vec![Inline::Strong(children)],
            Some(InlineKind::Link(Some(href))) => {
                let mut children = children;
                // Plain text made a URL inert, so what you read was what you
                // got. A link does not, and this is the screen where somebody
                // decides whether to send money to a stranger.
                if let Some(note) = disagreeing_host_note(&href, &children) {
                    children.push(Inline::Text(note));
                }
                vec![Inline::Link { href, children }]
            }
            // A refused link keeps its text, so a reader sees what was
            // written rather than a gap.
            Some(InlineKind::Link(None)) => children,
            Some(InlineKind::Plain) | None => children,
        };
        match self.inlines.last_mut() {
            Some(parent) => parent.extend(finished),
            // Emphasis outside any block: keep it rather than drop it.
            None => {
                if !finished.is_empty() {
                    self.push_block(Block::Paragraph(finished));
                }
            }
        }
    }

    /// Close an implicit paragraph, if one is open.
    fn flush_implicit(&mut self) {
        if matches!(self.kinds.last(), Some(InlineKind::ImplicitParagraph)) {
            self.end_inline();
        }
    }

    fn start_block_container(&mut self) {
        self.flush_implicit();
        if self.depth() >= MAX_DEPTH {
            self.truncated = true;
            self.suppressed += 1;
            return;
        }
        self.blocks.push(Vec::new());
    }

    fn end_block_container(&mut self) -> Vec<Block> {
        self.flush_implicit();
        // Never the document container: `blocks[0]` is what `finish` returns.
        if self.blocks.len() == 1 {
            return Vec::new();
        }
        self.blocks.pop().unwrap_or_default()
    }

    fn finish(mut self) -> Vec<Block> {
        self.flush_implicit();
        if self.truncated {
            self.push_block(Block::Paragraph(vec![Inline::Text(
                "[\u{2026} the rest of this description is not shown]".to_string(),
            )]));
        }
        self.blocks.into_iter().next().unwrap_or_default()
    }
}

/// Parse `source` into the subset this module can render.
pub fn parse(source: &str) -> Vec<Block> {
    // Deliberately no table, footnote or task-list extensions: each is more
    // surface for no gain in a store description. Raw HTML cannot be switched
    // off in the parser, so it is dropped below instead.
    let mut b = Builder::new();
    // Cut on a character boundary, so the parser is never handed half a
    // code point.
    let (source, cut) = if source.len() > MAX_SOURCE_BYTES {
        let mut end = MAX_SOURCE_BYTES;
        while end > 0 && !source.is_char_boundary(end) {
            end -= 1;
        }
        (&source[..end], true)
    } else {
        (source, false)
    };
    b.truncated = cut;

    for event in Parser::new_ext(source, Options::empty()) {
        if b.nodes >= MAX_NODES {
            b.truncated = true;
            break;
        }
        match event {
            Event::Start(Tag::Paragraph) => b.start_inline(InlineKind::Paragraph),
            Event::Start(Tag::Heading { level, .. }) => {
                b.start_inline(InlineKind::Heading(demote(level)))
            }
            Event::Start(Tag::Emphasis) => b.start_inline(InlineKind::Emphasis),
            Event::Start(Tag::Strong) => b.start_inline(InlineKind::Strong),
            Event::Start(Tag::Link { dest_url, .. }) => {
                b.start_inline(InlineKind::Link(safe_href(&dest_url)))
            }
            // Only the alt text, which arrives as the image's children.
            Event::Start(Tag::Image { .. }) => b.start_inline(InlineKind::Plain),
            Event::Start(Tag::BlockQuote(_)) | Event::Start(Tag::Item) => b.start_block_container(),
            Event::Start(Tag::List(first)) => {
                b.flush_implicit();
                if b.depth() >= MAX_DEPTH {
                    b.truncated = true;
                    b.suppressed += 1;
                } else {
                    b.lists.push((first.is_some(), Vec::new()));
                }
            }
            Event::Start(Tag::CodeBlock(_)) => {
                b.flush_implicit();
                b.code = Some(String::new());
            }

            Event::End(
                TagEnd::Paragraph
                | TagEnd::Heading(_)
                | TagEnd::Emphasis
                | TagEnd::Strong
                | TagEnd::Link
                | TagEnd::Image,
            ) => {
                if !b.end_was_suppressed() {
                    b.end_inline();
                }
            }
            Event::End(TagEnd::BlockQuote(_)) => {
                if !b.end_was_suppressed() {
                    let inner = b.end_block_container();
                    if !inner.is_empty() {
                        b.push_block(Block::Quote(inner));
                    }
                }
            }
            Event::End(TagEnd::Item) => {
                if !b.end_was_suppressed() {
                    let item = b.end_block_container();
                    if let Some((_, items)) = b.lists.last_mut() {
                        items.push(item);
                    }
                }
            }
            Event::End(TagEnd::List(_)) => {
                if !b.end_was_suppressed() {
                    if let Some((ordered, items)) = b.lists.pop() {
                        if !items.is_empty() {
                            b.push_block(Block::List { ordered, items });
                        }
                    }
                }
            }
            Event::End(TagEnd::CodeBlock) => {
                if let Some(text) = b.code.take() {
                    b.push_block(Block::Code(text));
                }
            }

            Event::Text(text) => match b.code.as_mut() {
                Some(buffer) => buffer.push_str(&text),
                None => b.push_inline(Inline::Text(text.to_string())),
            },
            Event::Code(text) => b.push_inline(Inline::Code(text.to_string())),
            // A source line break reads as a space, the way markdown means it.
            Event::SoftBreak => b.push_inline(Inline::Text(" ".to_string())),
            Event::HardBreak => b.push_inline(Inline::Break),
            Event::Rule => {
                b.flush_implicit();
                b.push_block(Block::Rule);
            }

            // The tree has no node for markup, so a seller's tags arrive as
            // literal text: visible, inert, and not silently swallowing the
            // rest of the description the way dropping an HTML block did.
            Event::Html(text) | Event::InlineHtml(text) => {
                b.push_inline(Inline::Text(text.to_string()))
            }
            _ => {}
        }
    }

    b.finish()
}

/// Render a seller's description.
#[component]
pub fn Markdown(source: String, class: String) -> Element {
    let blocks = parse(&source);
    rsx! {
        div { class: "{class}", {render_blocks(&blocks)} }
    }
}

fn render_blocks(blocks: &[Block]) -> Element {
    rsx! {
        for block in blocks.iter() {
            {render_block(block)}
        }
    }
}

fn render_block(block: &Block) -> Element {
    match block {
        Block::Paragraph(children) => rsx! { p { {render_inlines(children)} } },
        Block::Heading { level, children } => match level {
            4 => rsx! { h4 { {render_inlines(children)} } },
            5 => rsx! { h5 { {render_inlines(children)} } },
            _ => rsx! { h6 { {render_inlines(children)} } },
        },
        Block::Code(text) => rsx! { pre { code { "{text}" } } },
        Block::Quote(inner) => rsx! { blockquote { {render_blocks(inner)} } },
        Block::List { ordered, items } => {
            if *ordered {
                rsx! {
                    ol {
                        for item in items.iter() {
                            li { {render_blocks(item)} }
                        }
                    }
                }
            } else {
                rsx! {
                    ul {
                        for item in items.iter() {
                            li { {render_blocks(item)} }
                        }
                    }
                }
            }
        }
        Block::Rule => rsx! { hr {} },
    }
}

fn render_inlines(inlines: &[Inline]) -> Element {
    rsx! {
        for inline in inlines.iter() {
            {render_inline(inline)}
        }
    }
}

fn render_inline(inline: &Inline) -> Element {
    match inline {
        Inline::Text(text) => rsx! { "{text}" },
        Inline::Code(text) => rsx! { code { "{text}" } },
        Inline::Emphasis(children) => rsx! { em { {render_inlines(children)} } },
        Inline::Strong(children) => rsx! { strong { {render_inlines(children)} } },
        // `noopener` because a seller's link must not get a handle on this
        // page, and `nofollow` because a store description is user content.
        Inline::Link { href, children } => rsx! {
            a {
                href: "{href}",
                target: "_blank",
                rel: "noopener noreferrer nofollow",
                {render_inlines(children)}
            }
        },
        Inline::Break => rsx! { br {} },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(s: &str) -> Inline {
        Inline::Text(s.to_string())
    }

    /// **Raw HTML a seller typed can only ever be text.**
    ///
    /// The reason this module exists: rendering markdown to an HTML string
    /// would put this script in the page, in the app's own origin, next to the
    /// delegate connection. The tree has no node for markup, so the tags come
    /// through as characters a reader sees and a browser does not run.
    #[test]
    fn raw_html_can_only_be_text() {
        for source in [
            "<script>alert(1)</script>",
            "before <img src=x onerror=alert(1)> after",
            "<div onclick=\"steal()\">text</div>",
            "<iframe src=\"https://evil.example\"></iframe>",
            "<a href=\"javascript:alert(1)\">click</a>",
        ] {
            for block in parse(source) {
                let inlines = match block {
                    Block::Paragraph(inlines)
                    | Block::Heading {
                        children: inlines, ..
                    } => inlines,
                    other => panic!("{source:?} produced {other:?}, which is not text"),
                };
                for inline in inlines {
                    assert!(
                        matches!(inline, Inline::Text(_)),
                        "{source:?} produced {inline:?}, which is not text"
                    );
                }
            }
        }
    }

    /// **An HTML block does not swallow the description around it.**
    ///
    /// In CommonMark an HTML block runs to the next blank line and every line
    /// in it arrives as raw HTML, so dropping those events lost the seller's
    /// prose too: one stray `<div>` at the top emptied the whole description,
    /// silently, with no preview to notice it in.
    #[test]
    fn an_html_block_keeps_the_words_inside_it() {
        let rendered = format!("{:?}", parse("<div>\nBuy from my real shop\n</div>"));
        assert!(
            rendered.contains("Buy from my real shop"),
            "the seller's words went missing: {rendered}"
        );
    }

    #[test]
    fn a_link_that_is_code_is_not_clickable_but_keeps_its_text() {
        let blocks = parse("[click me](javascript:alert(1))");
        assert_eq!(blocks, vec![Block::Paragraph(vec![text("click me")])]);
        assert_eq!(safe_href("javascript:alert(1)"), None);
        assert_eq!(safe_href("data:text/html;base64,PHNjcmlwdD4="), None);
        assert_eq!(safe_href("JaVaScRiPt:alert(1)"), None);
        assert_eq!(safe_href("java\nscript:alert(1)"), None);
        // Relative and protocol-relative URLs resolve inside this app's own
        // origin, so they are refused too.
        assert_eq!(safe_href("/wallet"), None);
        assert_eq!(safe_href("//evil.example"), None);
    }

    #[test]
    fn an_ordinary_link_is_kept() {
        assert_eq!(
            parse("[docs](https://freenet.org/docs)"),
            vec![Block::Paragraph(vec![Inline::Link {
                href: "https://freenet.org/docs".to_string(),
                children: vec![text("docs")],
            }])]
        );
        assert_eq!(
            safe_href("mailto:seller@example.com").as_deref(),
            Some("mailto:seller@example.com")
        );
    }

    /// **A seller's heading cannot outrank the page's own.**
    #[test]
    fn headings_are_demoted() {
        let levels: Vec<u8> = parse("# One\n\n## Two\n\n### Three\n\n#### Four")
            .into_iter()
            .filter_map(|block| match block {
                Block::Heading { level, .. } => Some(level),
                _ => None,
            })
            .collect();
        assert_eq!(levels, vec![4, 4, 5, 6]);
    }

    #[test]
    fn an_image_contributes_only_its_alt_text() {
        assert_eq!(
            parse("![a tracking pixel](https://evil.example/p.gif)"),
            vec![Block::Paragraph(vec![text("a tracking pixel")])],
            "no request is made from a viewer's browser"
        );
    }

    #[test]
    fn lists_headings_emphasis_and_code_survive() {
        assert_eq!(
            parse("## Shipping\n\n- ships **fast**\n- ask *first*\n"),
            vec![
                Block::Heading {
                    level: 4,
                    children: vec![text("Shipping")],
                },
                Block::List {
                    ordered: false,
                    items: vec![
                        vec![Block::Paragraph(vec![
                            text("ships "),
                            Inline::Strong(vec![text("fast")]),
                        ])],
                        vec![Block::Paragraph(vec![
                            text("ask "),
                            Inline::Emphasis(vec![text("first")]),
                        ])],
                    ],
                },
            ]
        );
        assert_eq!(
            parse("1. first\n2. second\n"),
            vec![Block::List {
                ordered: true,
                items: vec![
                    vec![Block::Paragraph(vec![text("first")])],
                    vec![Block::Paragraph(vec![text("second")])],
                ],
            }]
        );
        assert_eq!(
            parse("use `--signet` here"),
            vec![Block::Paragraph(vec![
                text("use "),
                Inline::Code("--signet".to_string()),
                text(" here"),
            ])]
        );
    }

    /// A fenced block's contents are text, not markup to interpret.
    #[test]
    fn a_code_block_is_not_parsed_as_markdown() {
        assert_eq!(
            parse("```\n# not a heading\n<script>alert(1)</script>\n```"),
            vec![Block::Code(
                "# not a heading\n<script>alert(1)</script>\n".to_string()
            )]
        );
    }

    /// Plain text is the common case and must come through untouched, one
    /// paragraph per blank line, with wrapped lines read as one.
    #[test]
    fn plain_text_is_left_alone() {
        assert_eq!(
            parse("Hand-thrown mugs.\nMade to order.\n\nAsk before ordering."),
            vec![
                // One node, not three: runs are coalesced, so a description
                // cannot spend a DOM node per character.
                Block::Paragraph(vec![text("Hand-thrown mugs. Made to order.")]),
                Block::Paragraph(vec![text("Ask before ordering.")]),
            ]
        );
        assert_eq!(parse(""), vec![]);
        assert_eq!(parse("   \n  "), vec![]);
    }

    /// **Nesting is flattened rather than followed down.**
    ///
    /// The renderer recurses once per level, and so does dropping the tree,
    /// on a 1 MiB wasm stack where an overflow is an unrecoverable trap
    /// rather than a panic: it would kill the whole app, and since the text
    /// lives in contract state, reloading would kill it again. Two kilobytes
    /// of `>` nests fifty thousand deep, so this cap is what stands between a
    /// store link and a visitor's app.
    #[test]
    fn deep_nesting_is_flattened_and_never_recursed() {
        fn depth(blocks: &[Block]) -> usize {
            1 + blocks
                .iter()
                .map(|block| match block {
                    Block::Quote(inner) => depth(inner),
                    Block::List { items, .. } => {
                        items.iter().map(|item| depth(item)).max().unwrap_or(0)
                    }
                    _ => 0,
                })
                .max()
                .unwrap_or(0)
        }

        let quotes = parse(&">".repeat(50_000));
        assert!(
            depth(&quotes) <= MAX_DEPTH + 2,
            "{} levels deep, which recursion cannot be trusted with",
            depth(&quotes)
        );

        // Lists nest through two tags per level, so they are the other shape.
        let nested_lists: String = (0..2_000)
            .map(|i| format!("{}- x\n", " ".repeat(i * 2)))
            .collect();
        let lists = parse(&nested_lists);
        assert!(depth(&lists) <= MAX_DEPTH + 2, "{} levels", depth(&lists));
    }

    /// **One description cannot fill the page with nodes.**
    ///
    /// The parser emits an event per unmatched punctuation character, so a
    /// megabyte of `[` was a million DOM nodes before coalescing and the node
    /// budget. Both are needed: coalescing does nothing for a million
    /// paragraphs.
    #[test]
    fn a_description_is_bounded_in_nodes_and_in_length() {
        fn count(blocks: &[Block]) -> usize {
            blocks
                .iter()
                .map(|block| match block {
                    Block::Paragraph(inlines)
                    | Block::Heading {
                        children: inlines, ..
                    } => 1 + inlines.len(),
                    Block::Quote(inner) => 1 + count(inner),
                    Block::List { items, .. } => {
                        1 + items.iter().map(|item| count(item)).sum::<usize>()
                    }
                    _ => 1,
                })
                .sum()
        }

        for bomb in [
            "[".repeat(200_000),
            "a\n\n".repeat(100_000),
            "*x* ".repeat(100_000),
        ] {
            let nodes = count(&parse(&bomb));
            assert!(
                nodes <= MAX_NODES + 8,
                "{nodes} nodes from {} bytes of input",
                bomb.len()
            );
        }
    }

    /// And the reader is told, rather than left wondering where the rest went.
    #[test]
    fn a_cut_description_says_so() {
        let cut = format!("{:?}", parse(&"word ".repeat(100_000)));
        assert!(cut.contains("not shown"), "a cut description must say so");
        let whole = format!("{:?}", parse("a short description"));
        assert!(!whole.contains("not shown"), "an untouched one must not");
    }

    /// **A link to the machine the app runs on is refused.**
    ///
    /// A relative link is refused because it resolves inside the app's own
    /// origin; an absolute one naming that origin does the same thing, and a
    /// node serves its webapps from loopback. The shell opens a
    /// `target="_blank"` link as a real top-level tab, so this would be a
    /// one-click load of any contract webapp at the node's own origin -- a
    /// look-alike Harvest, say.
    #[test]
    fn a_link_to_this_machine_is_refused() {
        for url in [
            "http://127.0.0.1:50509/v1/contract/web/abc/",
            "http://localhost:7509/",
            "https://[::1]/",
            "http://192.168.1.4/",
            "http://10.0.0.1/",
            "http://172.20.1.1/",
            "http://169.254.1.1/",
            "http://node.local/",
            "http://freenet.org@127.0.0.1/",
        ] {
            assert_eq!(safe_href(url), None, "{url} names this machine");
        }
        // Somewhere else is still fine, including hosts that merely start
        // with the same digits.
        for url in [
            "https://freenet.org/",
            "http://172.32.0.1/",
            "http://1.2.3.4/",
            "https://not-localhost.example/",
        ] {
            assert!(safe_href(url).is_some(), "{url} is somewhere else");
        }
    }

    /// **A link whose text claims one address and goes to another says so.**
    #[test]
    fn a_link_that_disagrees_with_its_own_text_names_its_destination() {
        let blocks = parse("[https://freenet.org](https://evil.example/pay)");
        let Some(Block::Paragraph(inlines)) = blocks.first() else {
            panic!("{blocks:?}");
        };
        let Some(Inline::Link { children, .. }) = inlines.first() else {
            panic!("{inlines:?}");
        };
        assert_eq!(
            children.last(),
            Some(&text(" (goes to evil.example)")),
            "{children:?}"
        );

        // Ordinary link text says nothing about where it goes, so nothing is
        // added; nor when the text agrees, `www.` aside.
        for source in [
            "[my shop](https://evil.example)",
            "[https://freenet.org](https://freenet.org/docs)",
            "[www.freenet.org](https://freenet.org/)",
        ] {
            let rendered = format!("{:?}", parse(source));
            assert!(!rendered.contains("goes to"), "{source}: {rendered}");
        }
    }

    #[test]
    fn a_quote_and_a_rule_are_kept() {
        assert_eq!(
            parse("> quoted\n\n---\n"),
            vec![
                Block::Quote(vec![Block::Paragraph(vec![text("quoted")])]),
                Block::Rule,
            ]
        );
    }
}
