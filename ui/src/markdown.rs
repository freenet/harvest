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
//! represent cannot reach the page. Raw HTML has no representation at all and
//! is dropped.
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

use dioxus::prelude::*;
use pulldown_cmark::{Event, HeadingLevel, Options, Parser, Tag, TagEnd};

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
    (allowed && clean).then(|| trimmed.to_string())
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
}

impl Builder {
    fn new() -> Self {
        Builder {
            blocks: vec![Vec::new()],
            ..Builder::default()
        }
    }

    fn push_block(&mut self, block: Block) {
        self.blocks
            .last_mut()
            .expect("the document container is never popped")
            .push(block);
    }

    fn start_inline(&mut self, kind: InlineKind) {
        // A block-level start closes an implicit paragraph: the two cannot
        // nest, and leaving it open would swallow the new block's text.
        if matches!(kind, InlineKind::Paragraph | InlineKind::Heading(_)) {
            self.flush_implicit();
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
        self.inline_target().push(inline);
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
            Some(InlineKind::Link(Some(href))) => vec![Inline::Link { href, children }],
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
        self.blocks.push(Vec::new());
    }

    fn end_block_container(&mut self) -> Vec<Block> {
        self.flush_implicit();
        self.blocks.pop().unwrap_or_default()
    }

    fn finish(mut self) -> Vec<Block> {
        self.flush_implicit();
        self.blocks.into_iter().next().unwrap_or_default()
    }
}

/// Parse `source` into the subset this module can render.
pub fn parse(source: &str) -> Vec<Block> {
    // Deliberately no table, footnote or task-list extensions: each is more
    // surface for no gain in a store description. Raw HTML cannot be switched
    // off in the parser, so it is dropped below instead.
    let mut b = Builder::new();

    for event in Parser::new_ext(source, Options::empty()) {
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
                b.lists.push((first.is_some(), Vec::new()));
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
            ) => b.end_inline(),
            Event::End(TagEnd::BlockQuote(_)) => {
                let inner = b.end_block_container();
                if !inner.is_empty() {
                    b.push_block(Block::Quote(inner));
                }
            }
            Event::End(TagEnd::Item) => {
                let item = b.end_block_container();
                if let Some((_, items)) = b.lists.last_mut() {
                    items.push(item);
                }
            }
            Event::End(TagEnd::List(_)) => {
                if let Some((ordered, items)) = b.lists.pop() {
                    if !items.is_empty() {
                        b.push_block(Block::List { ordered, items });
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

            // Raw HTML has no representation in the tree above, which is the
            // whole point: a `<script>` a seller typed cannot reach the page.
            Event::Html(_) | Event::InlineHtml(_) => {}
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

    /// **Raw HTML a seller typed never reaches the tree.**
    ///
    /// The reason this module exists. Markdown allows raw HTML, so rendering
    /// to an HTML string would put this script in the page, in the app's own
    /// origin, next to the delegate connection.
    #[test]
    fn raw_html_is_dropped() {
        for source in [
            "<script>alert(1)</script>",
            "before <img src=x onerror=alert(1)> after",
            "<div onclick=\"steal()\">text</div>",
            "<iframe src=\"https://evil.example\"></iframe>",
        ] {
            let rendered = format!("{:?}", parse(source));
            for forbidden in ["script", "onerror", "onclick", "iframe"] {
                assert!(
                    !rendered.contains(forbidden),
                    "{forbidden:?} survived parsing {source:?}: {rendered}"
                );
            }
        }
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
                Block::Paragraph(vec![
                    text("Hand-thrown mugs."),
                    text(" "),
                    text("Made to order."),
                ]),
                Block::Paragraph(vec![text("Ask before ordering.")]),
            ]
        );
        assert_eq!(parse(""), vec![]);
        assert_eq!(parse("   \n  "), vec![]);
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
