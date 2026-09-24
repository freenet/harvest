mod app;
pub(crate) mod bitcoin_view;
pub(crate) mod buy_view;
mod invoice_form;
mod listing_form;
pub(crate) mod message_view;
pub(crate) mod my_store;
pub(crate) mod purchases_view;
mod reputation_view;
mod seller_listings;
mod store_view;

pub use app::App;
// Minting the seller's messaging key. Lives beside the store-creation flow
// that first needs it; `state` calls it again whenever a ghostkey connects.
pub(crate) use my_store::{ensure_encryption_key, mint_encryption_key};

#[cfg(test)]
mod css_spacing_tests {
    //! `harvest.css` puts a margin between stacked siblings, and switches it
    //! off inside flex and grid containers, where `gap` does that job and a
    //! margin would push one item out of line. The switch-off names each
    //! container, so a container made flex later without being added there
    //! silently gets misaligned children. This keeps the list complete.

    const CSS: &str = include_str!("../../assets/harvest.css");

    fn strip_comments(css: &str) -> String {
        let mut out = String::with_capacity(css.len());
        let mut rest = css;
        while let Some(start) = rest.find("/*") {
            out.push_str(&rest[..start]);
            // An unterminated comment would silently drop the rest of the
            // file, and every container in it, from the check.
            let end = rest[start + 2..]
                .find("*/")
                .expect("unterminated /* comment in harvest.css");
            rest = &rest[start + 2 + end + 2..];
        }
        out.push_str(rest);
        out
    }

    /// Every innermost `selectors { declarations }` rule, including those
    /// nested in `@media`.
    fn rules(css: &str) -> Vec<(String, String)> {
        let mut found = Vec::new();
        let mut prelude_start = 0;
        let mut open: Option<usize> = None;
        for (i, c) in css.char_indices() {
            match c {
                '{' => {
                    // A brace inside an open one: the outer was an `@media`
                    // prelude, a block of rules, and this rule's selectors
                    // start after it.
                    if let Some(o) = open {
                        prelude_start = o + 1;
                    }
                    open = Some(i);
                }
                '}' => {
                    if let Some(o) = open.take() {
                        let prelude = css[prelude_start..o].trim().to_string();
                        found.push((prelude, css[o + 1..i].to_string()));
                    }
                    prelude_start = i + 1;
                }
                _ => {}
            }
        }
        found
    }

    fn normalise(selector: &str) -> String {
        selector.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    /// Top-level commas only: `:where(a, b) > *` is one selector.
    fn split_selectors(list: &str) -> Vec<String> {
        let mut out = Vec::new();
        let mut depth = 0;
        let mut start = 0;
        for (i, c) in list.char_indices() {
            match c {
                '(' => depth += 1,
                ')' => depth -= 1,
                ',' if depth == 0 => {
                    out.push(normalise(&list[start..i]));
                    start = i + 1;
                }
                _ => {}
            }
        }
        out.push(normalise(&list[start..]));
        out
    }

    #[test]
    fn every_flex_or_grid_container_opts_out_of_sibling_margins() {
        let css = strip_comments(CSS);
        let rules = rules(&css);

        let opt_out = rules
            .iter()
            .find(|(prelude, body)| {
                prelude.starts_with(":where(")
                    && prelude.ends_with(") > *")
                    && body.contains("margin-top: 0;")
                    && body.contains("margin-left: 0;")
            })
            .expect("the flex/grid opt-out rule is missing from harvest.css");
        let inner = &opt_out.0[":where(".len()..opt_out.0.len() - ") > *".len()];
        let listed = split_selectors(inner);
        assert!(listed.len() > 10, "opt-out list parsed as {listed:?}");

        let mut missing = Vec::new();
        for (prelude, body) in &rules {
            let is_container = body.split(';').any(|decl| {
                // `display:flex`, `display : flex !important` and the like
                // all count.
                let Some((property, value)) = decl.split_once(':') else {
                    return false;
                };
                let value = value.replace("!important", "");
                property.trim() == "display"
                    && ["flex", "grid", "inline-flex", "inline-grid"].contains(&value.trim())
            });
            if !is_container {
                continue;
            }
            for selector in split_selectors(prelude) {
                if !listed.contains(&selector) {
                    missing.push(selector);
                }
            }
        }
        assert!(
            missing.is_empty(),
            "flex/grid containers not in harvest.css's sibling-margin opt-out: {missing:?}"
        );
    }

    /// A container made flex or grid by an inline `style:` in the markup is
    /// invisible to the check above, and its children would get the sibling
    /// margins on top of its gap. Use a class (`form-actions`, `row-between`,
    /// ...) instead.
    #[test]
    fn no_markup_makes_a_flex_or_grid_container_inline() {
        // Every component file, read at test time so a new one is covered.
        // This file is skipped: its own needles would match.
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/src/components");
        let mut sources = Vec::new();
        for entry in std::fs::read_dir(dir).expect("components dir") {
            let path = entry.expect("dir entry").path();
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            if name.ends_with(".rs") && name != "mod.rs" {
                sources.push((
                    name,
                    std::fs::read_to_string(&path).expect("read component"),
                ));
            }
        }
        assert!(
            sources.len() >= 10,
            "found only {} component files",
            sources.len()
        );
        let mut offending = Vec::new();
        for (file, source) in &sources {
            for (n, line) in source.lines().enumerate() {
                let Some(at) = line.find("style:") else {
                    continue;
                };
                let compact: String = line[at..].chars().filter(|c| !c.is_whitespace()).collect();
                if [
                    "display:flex",
                    "display:grid",
                    "display:inline-flex",
                    "display:inline-grid",
                ]
                .iter()
                .any(|d| compact.contains(d))
                {
                    offending.push(format!("{file}:{}", n + 1));
                }
            }
        }
        assert!(
            offending.is_empty(),
            "inline flex/grid containers (give them a class in harvest.css instead): {offending:?}"
        );
    }

    #[test]
    fn the_parser_sees_the_containers_it_is_meant_to_check() {
        // Guards the guard: a parser that found no containers would pass the
        // test above vacuously.
        let css = strip_comments(CSS);
        let containers: Vec<String> = rules(&css)
            .into_iter()
            .filter(|(_, body)| body.contains("display: flex") || body.contains("display: grid"))
            .flat_map(|(prelude, _)| split_selectors(&prelude))
            .collect();
        for expected in [
            ".form-actions",
            ".row-between",
            ".share-row",
            ".checklist li",
        ] {
            assert!(
                containers.iter().any(|c| c == expected),
                "{expected} not seen; parsed {containers:?}"
            );
        }
    }
}
