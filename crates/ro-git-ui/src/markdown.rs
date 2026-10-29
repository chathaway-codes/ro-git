//! Client-side CommonMark + GitHub Flavored Markdown (GFM) rendering engine.
//!
//! Maps [`pulldown_cmark::Parser`] events directly into Yew [`Html`] ([`VNode`])
//! trees without `innerHTML` or [`VNode::from_html_unchecked`], neutralizing raw
//! HTML injection and unsafe URI schemes while rewriting relative repository links
//! and image paths against [`MarkdownContext`].

use pulldown_cmark::{Alignment, CodeBlockKind, Event, HeadingLevel, Options, Parser, Tag, TagEnd};
use ro_git_proto::strip_git_suffix;
use yew::prelude::*;
use yew::virtual_dom::{VList, VNode, VTag, VText};

/// Repository and directory context used to resolve relative links and image URLs
/// when rendering Markdown documents inside a repository.
#[derive(Clone, Debug, PartialEq)]
pub struct MarkdownContext {
    pub scope: String,
    pub owner: String,
    pub visibility: String,
    pub repo: String,
    pub revision: String,
    pub current_dir: String,
    pub on_navigate: Option<Callback<String>>,
}

impl MarkdownContext {
    /// Creates a normalized [`MarkdownContext`] for a repository revision and directory path.
    #[must_use]
    pub fn new(
        scope: &str,
        owner: &str,
        visibility: &str,
        repo: &str,
        revision: &str,
        current_dir: &str,
    ) -> Self {
        let clean_rev = revision.trim();
        Self {
            scope: scope.trim().trim_matches('/').to_owned(),
            owner: owner.trim().trim_matches('/').to_owned(),
            visibility: visibility.trim().trim_matches('/').to_owned(),
            repo: strip_git_suffix(repo.trim().trim_matches('/')).to_owned(),
            revision: if clean_rev.is_empty() {
                "HEAD".to_owned()
            } else {
                clean_rev.trim_matches('/').to_owned()
            },
            current_dir: normalize_repo_path("", current_dir),
            on_navigate: None,
        }
    }

    /// Attaches an optional SPA navigation callback invoked when a user clicks a
    /// rewritten internal repository link.
    #[must_use]
    pub fn with_on_navigate(mut self, on_navigate: Callback<String>) -> Self {
        self.on_navigate = Some(on_navigate);
        self
    }

    /// Formats the repository tree route for `resolved_path` (`""` for the repository root).
    #[must_use]
    pub fn tree_route(&self, resolved_path: &str) -> String {
        let clean = resolved_path.trim_matches('/');
        if clean.is_empty() {
            format!(
                "/{}/{}/{}/{}/tree/{}",
                self.scope, self.owner, self.visibility, self.repo, self.revision
            )
        } else {
            format!(
                "/{}/{}/{}/{}/tree/{}/{}",
                self.scope, self.owner, self.visibility, self.repo, self.revision, clean
            )
        }
    }

    /// Formats the repository blob route for `resolved_path`.
    #[must_use]
    pub fn blob_route(&self, resolved_path: &str) -> String {
        let clean = resolved_path.trim_matches('/');
        if clean.is_empty() {
            self.tree_route("")
        } else {
            format!(
                "/{}/{}/{}/{}/blob/{}/{}",
                self.scope, self.owner, self.visibility, self.repo, self.revision, clean
            )
        }
    }
}

/// Returns the [`pulldown_cmark::Options`] configured with CommonMark + GFM extensions
/// (tables, task lists, and strikethrough).
#[must_use]
pub fn markdown_options() -> Options {
    let mut options = Options::empty();
    options.insert(Options::ENABLE_TABLES);
    options.insert(Options::ENABLE_TASKLISTS);
    options.insert(Options::ENABLE_STRIKETHROUGH);
    options.insert(Options::ENABLE_HEADING_ATTRIBUTES);
    options
}

/// Normalizes a repository-relative path against `base_dir`, resolving `.` and `..`
/// segments while clamping at the repository root so traversal (`../../../etc/passwd`)
/// can never escape the root.
#[must_use]
pub fn normalize_repo_path(base_dir: &str, relative_path: &str) -> String {
    let mut segments: Vec<&str> = Vec::new();
    let rel_trimmed = relative_path.trim();

    if !rel_trimmed.starts_with('/') {
        for seg in base_dir.trim().split('/') {
            match seg {
                "" | "." => {}
                ".." => {
                    segments.pop();
                }
                other => segments.push(other),
            }
        }
    }

    for seg in rel_trimmed.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            other => segments.push(other),
        }
    }

    segments.join("/")
}

/// Decodes numeric/hex HTML character references and `&colon;` while stripping
/// ASCII whitespace and control characters for scheme inspection.
#[must_use]
fn decode_for_scheme_check(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == b'&' {
            if let Some(rel_end) = bytes[i..].iter().position(|&b| b == b';') {
                let entity = &input[i + 1..i + rel_end];
                if let Some(decoded) = decode_html_entity(entity) {
                    if !decoded.is_control() && !decoded.is_ascii_whitespace() {
                        out.push(decoded);
                    }
                    i += rel_end + 1;
                    continue;
                }
            }
        }
        let ch = input[i..].chars().next().unwrap_or('\0');
        if !ch.is_control() && !ch.is_ascii_whitespace() {
            out.push(ch);
        }
        i += ch.len_utf8();
    }

    out
}

#[must_use]
fn decode_html_entity(entity: &str) -> Option<char> {
    if entity.eq_ignore_ascii_case("colon") {
        return Some(':');
    }
    if entity.eq_ignore_ascii_case("tab") || entity.eq_ignore_ascii_case("newline") {
        return Some(' ');
    }
    let num_str = entity.strip_prefix('#')?;
    let code = if let Some(hex) = num_str
        .strip_prefix('x')
        .or_else(|| num_str.strip_prefix('X'))
    {
        u32::from_str_radix(hex, 16).ok()?
    } else {
        num_str.parse::<u32>().ok()?
    };
    char::from_u32(code)
}

#[must_use]
fn has_scheme_prefix(s: &str) -> bool {
    for b in s.bytes() {
        match b {
            b':' => return true,
            b'/' | b'?' | b'#' => return false,
            _ => {}
        }
    }
    false
}

#[must_use]
fn is_directory_target(path_part: &str) -> bool {
    path_part.ends_with('/')
        || path_part == "."
        || path_part == ".."
        || path_part.ends_with("/.")
        || path_part.ends_with("/..")
}

#[must_use]
fn is_valid_http_target(rest: &str) -> bool {
    !rest.is_empty()
        && !rest.starts_with('/')
        && !rest.chars().any(|c| c.is_control() || c.is_whitespace())
}

/// Returns `true` if `raw_url` uses a safe URL scheme or is a safe relative path.
#[must_use]
pub fn is_safe_markdown_url(raw_url: &str, is_image: bool) -> bool {
    resolve_markdown_url(raw_url, None, is_image).is_some()
}

/// Validates and resolves a Markdown link or image URL against an optional [`MarkdownContext`].
///
/// - Allows `http://`, `https://`, `mailto:` (for links), `#fragment` (for links),
///   and relative repository paths.
/// - Rejects `javascript:`, `vbscript:`, `data:`, `file:`, unknown `<scheme>:`,
///   protocol-relative `//...`, control-character/whitespace obfuscations, and HTML
///   entity-encoded scheme bypasses.
/// - Resolves relative repository paths against `ctx` (clamping `..` at the repository
///   root) into `/{scope}/{owner}/{visibility}/{repo}/blob/{revision}/{path}` or
///   `/{scope}/{owner}/{visibility}/{repo}/tree/{revision}/{path}` for directory targets.
#[must_use]
pub fn resolve_markdown_url(
    raw_url: &str,
    ctx: Option<&MarkdownContext>,
    is_image: bool,
) -> Option<String> {
    let trimmed = raw_url.trim();
    if trimmed.is_empty() {
        return None;
    }

    // Reject control characters and backslashes anywhere in the URL.
    if trimmed.chars().any(|c| c.is_control() || c == '\\') {
        return None;
    }

    // Reject protocol-relative URLs (`//evil.example.com`).
    let normalized_check = decode_for_scheme_check(trimmed);
    if trimmed.starts_with("//") || normalized_check.starts_with("//") {
        return None;
    }

    // Reject HTML entity-encoded schemes in raw unparsed URLs (`&#x6a;avascript:...`).
    if trimmed.contains('&') && has_scheme_prefix(&normalized_check) {
        let lower = normalized_check.to_ascii_lowercase();
        let allowed_encoded = lower.starts_with("http://")
            || lower.starts_with("https://")
            || (!is_image && lower.starts_with("mailto:"));
        if !allowed_encoded {
            return None;
        }
    }

    // Allow in-page `#fragment` anchors for links (not images).
    if trimmed.starts_with('#') {
        if is_image {
            return None;
        }
        return Some(trimmed.to_owned());
    }

    // Check explicit URI schemes (`<scheme>:...`).
    if has_scheme_prefix(trimmed) || has_scheme_prefix(&normalized_check) {
        let lower = trimmed.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("https://") {
            return is_valid_http_target(rest).then(|| trimmed.to_owned());
        }
        if let Some(rest) = lower.strip_prefix("http://") {
            return is_valid_http_target(rest).then(|| trimmed.to_owned());
        }
        if !is_image {
            if let Some(rest) = lower.strip_prefix("mailto:") {
                let valid = !rest.is_empty()
                    && !rest.starts_with('/')
                    && !rest.chars().any(|c| c.is_control() || c.is_whitespace());
                return valid.then(|| trimmed.to_owned());
            }
        }
        return None;
    }

    // Relative repository path: split optional `#fragment` and `?query`.
    let (path_and_query, fragment_opt) = match trimmed.split_once('#') {
        Some((p, f)) => (p, Some(f)),
        None => (trimmed, None),
    };
    let (path_part, query_opt) = match path_and_query.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (path_and_query, None),
    };

    if path_part.is_empty() {
        if is_image {
            return None;
        }
        let mut out = String::new();
        if let Some(q) = query_opt.filter(|q| !q.is_empty()) {
            out.push('?');
            out.push_str(q);
        }
        if let Some(f) = fragment_opt {
            out.push('#');
            out.push_str(f);
        }
        return (!out.is_empty()).then_some(out);
    }

    let is_dir = is_directory_target(path_part);
    if is_image && is_dir {
        return None;
    }

    let base_dir = ctx.map_or("", |c| c.current_dir.as_str());
    let resolved_path = normalize_repo_path(base_dir, path_part);

    let mut resolved = if let Some(context) = ctx {
        if is_dir {
            context.tree_route(&resolved_path)
        } else {
            context.blob_route(&resolved_path)
        }
    } else if is_dir {
        if resolved_path.is_empty() {
            "./".to_owned()
        } else {
            format!("{resolved_path}/")
        }
    } else {
        resolved_path
    };

    if resolved.is_empty() {
        return None;
    }

    if let Some(q) = query_opt.filter(|q| !q.is_empty()) {
        resolved.push('?');
        resolved.push_str(q);
    }
    if let Some(frag) = fragment_opt.filter(|f| !f.is_empty()) {
        resolved.push('#');
        resolved.push_str(frag);
    }

    Some(resolved)
}

#[must_use]
fn is_relative_repo_target(raw_url: &str) -> bool {
    let trimmed = raw_url.trim();
    !trimmed.is_empty()
        && !trimmed.starts_with('#')
        && !trimmed.starts_with("//")
        && !has_scheme_prefix(trimmed)
        && !has_scheme_prefix(&decode_for_scheme_check(trimmed))
}

#[must_use]
fn sanitize_code_language(info: &str) -> Option<String> {
    let token = info.split_whitespace().next()?.split(',').next()?.trim();
    if token.is_empty() {
        return None;
    }
    let clean: String = token
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '+' | '#' | '.'))
        .collect();
    (!clean.is_empty()).then_some(clean)
}

#[must_use]
fn alignment_str(alignment: Alignment) -> Option<&'static str> {
    match alignment {
        Alignment::None => None,
        Alignment::Left => Some("left"),
        Alignment::Center => Some("center"),
        Alignment::Right => Some("right"),
    }
}

#[must_use]
fn heading_tag_name(level: HeadingLevel) -> &'static str {
    match level {
        HeadingLevel::H1 => "h1",
        HeadingLevel::H2 => "h2",
        HeadingLevel::H3 => "h3",
        HeadingLevel::H4 => "h4",
        HeadingLevel::H5 => "h5",
        HeadingLevel::H6 => "h6",
    }
}

enum Frame {
    Root {
        children: Vec<VNode>,
    },
    Tag {
        tag: VTag,
        children: Vec<VNode>,
    },
    CodeBlock {
        language: Option<String>,
        text: String,
    },
    Table {
        alignments: Vec<Alignment>,
        in_head: bool,
        head_cells: Vec<VNode>,
        body_rows: Vec<VNode>,
        current_row_cells: Vec<VNode>,
        col_index: usize,
    },
    TableCell {
        is_header: bool,
        align: Option<&'static str>,
        children: Vec<VNode>,
    },
    Link {
        resolved_href: Option<String>,
        is_internal: bool,
        title: String,
        children: Vec<VNode>,
    },
    Image {
        resolved_src: Option<String>,
        title: String,
        alt_text: String,
    },
}

impl Frame {
    fn push_child(&mut self, node: VNode) {
        match self {
            Self::Root { children }
            | Self::Tag { children, .. }
            | Self::TableCell { children, .. }
            | Self::Link { children, .. } => children.push(node),
            Self::CodeBlock { text, .. } => {
                if let VNode::VText(vtext) = node {
                    text.push_str(vtext.text.as_str());
                }
            }
            Self::Image { alt_text, .. } => {
                append_plain_text(&node, alt_text);
            }
            Self::Table {
                in_head,
                head_cells,
                current_row_cells,
                ..
            } => {
                if *in_head {
                    head_cells.push(node);
                } else {
                    current_row_cells.push(node);
                }
            }
        }
    }

    fn push_text(&mut self, s: &str) {
        match self {
            Self::CodeBlock { text, .. } => text.push_str(s),
            Self::Image { alt_text, .. } => alt_text.push_str(s),
            _ => self.push_child(VNode::from(VText::new(s.to_owned()))),
        }
    }
}

fn append_plain_text(node: &VNode, out: &mut String) {
    match node {
        VNode::VText(vtext) => out.push_str(vtext.text.as_str()),
        VNode::VTag(vtag) => {
            if let Some(children) = vtag.children() {
                append_plain_text(children, out);
            }
        }
        VNode::VList(vlist) => {
            for child in vlist.iter() {
                append_plain_text(child, out);
            }
        }
        _ => {}
    }
}

fn mark_enclosing_list_item_as_task(stack: &mut [Frame]) {
    for frame in stack.iter_mut().rev() {
        if let Frame::Tag { tag, .. } = frame {
            if tag.tag() == "li" {
                tag.add_attribute("class", "task-list-item");
                break;
            }
        }
    }
}

/// Renders a Markdown document (`CommonMark` + GFM) directly into a Yew [`Html`] ([`VNode`]) tree.
///
/// - Never uses `innerHTML` or [`VNode::from_html_unchecked`].
/// - Neutralizes raw inline and block HTML (`<script>`, `<img onerror=...>`, etc.) by
///   converting raw HTML tokens into literal [`VText`] nodes.
/// - Filters unsafe URL schemes (`javascript:`, `data:`, `vbscript:`, `file:`, `//...`)
///   and rewrites relative repository links and images using `ctx`.
pub fn render_markdown(markdown: &str, ctx: Option<&MarkdownContext>) -> Html {
    let parser = Parser::new_ext(markdown, markdown_options());
    let mut stack: Vec<Frame> = vec![Frame::Root {
        children: Vec::new(),
    }];

    for event in parser {
        match event {
            Event::Start(tag) => match tag {
                Tag::Paragraph => {
                    stack.push(Frame::Tag {
                        tag: VTag::new("p"),
                        children: Vec::new(),
                    });
                }
                Tag::Heading {
                    level, id, classes, ..
                } => {
                    let mut vtag = VTag::new(heading_tag_name(level));
                    if let Some(id_val) = id.filter(|s| !s.is_empty()) {
                        vtag.add_attribute("id", id_val.into_string());
                    }
                    if !classes.is_empty() {
                        let joined: Vec<&str> = classes.iter().map(AsRef::as_ref).collect();
                        vtag.add_attribute("class", joined.join(" "));
                    }
                    stack.push(Frame::Tag {
                        tag: vtag,
                        children: Vec::new(),
                    });
                }
                Tag::BlockQuote(_) => {
                    stack.push(Frame::Tag {
                        tag: VTag::new("blockquote"),
                        children: Vec::new(),
                    });
                }
                Tag::CodeBlock(kind) => {
                    let language = match kind {
                        CodeBlockKind::Indented => None,
                        CodeBlockKind::Fenced(info) => sanitize_code_language(&info),
                    };
                    stack.push(Frame::CodeBlock {
                        language,
                        text: String::new(),
                    });
                }
                Tag::HtmlBlock => {
                    let mut vtag = VTag::new("div");
                    vtag.add_attribute("class", "markdown-raw-html");
                    stack.push(Frame::Tag {
                        tag: vtag,
                        children: Vec::new(),
                    });
                }
                Tag::List(start_opt) => {
                    let vtag = match start_opt {
                        Some(start) => {
                            let mut ol = VTag::new("ol");
                            if start != 1 {
                                ol.add_attribute("start", start.to_string());
                            }
                            ol
                        }
                        None => VTag::new("ul"),
                    };
                    stack.push(Frame::Tag {
                        tag: vtag,
                        children: Vec::new(),
                    });
                }
                Tag::Item => {
                    stack.push(Frame::Tag {
                        tag: VTag::new("li"),
                        children: Vec::new(),
                    });
                }
                Tag::Table(alignments) => {
                    stack.push(Frame::Table {
                        alignments,
                        in_head: false,
                        head_cells: Vec::new(),
                        body_rows: Vec::new(),
                        current_row_cells: Vec::new(),
                        col_index: 0,
                    });
                }
                Tag::TableHead => {
                    if let Some(Frame::Table {
                        in_head, col_index, ..
                    }) = stack.last_mut()
                    {
                        *in_head = true;
                        *col_index = 0;
                    }
                }
                Tag::TableRow => {
                    if let Some(Frame::Table {
                        in_head,
                        current_row_cells,
                        col_index,
                        ..
                    }) = stack.last_mut()
                    {
                        *in_head = false;
                        current_row_cells.clear();
                        *col_index = 0;
                    }
                }
                Tag::TableCell => {
                    let (is_header, align) = match stack.last_mut() {
                        Some(Frame::Table {
                            alignments,
                            in_head,
                            col_index,
                            ..
                        }) => {
                            let a = alignments.get(*col_index).copied().and_then(alignment_str);
                            *col_index += 1;
                            (*in_head, a)
                        }
                        _ => (false, None),
                    };
                    stack.push(Frame::TableCell {
                        is_header,
                        align,
                        children: Vec::new(),
                    });
                }
                Tag::Emphasis => {
                    stack.push(Frame::Tag {
                        tag: VTag::new("em"),
                        children: Vec::new(),
                    });
                }
                Tag::Strong => {
                    stack.push(Frame::Tag {
                        tag: VTag::new("strong"),
                        children: Vec::new(),
                    });
                }
                Tag::Strikethrough => {
                    stack.push(Frame::Tag {
                        tag: VTag::new("del"),
                        children: Vec::new(),
                    });
                }
                Tag::Link {
                    dest_url, title, ..
                } => {
                    let is_internal = ctx.is_some() && is_relative_repo_target(&dest_url);
                    let resolved_href = resolve_markdown_url(&dest_url, ctx, false);
                    stack.push(Frame::Link {
                        resolved_href,
                        is_internal,
                        title: title.into_string(),
                        children: Vec::new(),
                    });
                }
                Tag::Image {
                    dest_url, title, ..
                } => {
                    let resolved_src = resolve_markdown_url(&dest_url, ctx, true);
                    stack.push(Frame::Image {
                        resolved_src,
                        title: title.into_string(),
                        alt_text: String::new(),
                    });
                }
                Tag::FootnoteDefinition(_)
                | Tag::DefinitionList
                | Tag::DefinitionListTitle
                | Tag::DefinitionListDefinition
                | Tag::MetadataBlock(_) => {
                    stack.push(Frame::Tag {
                        tag: VTag::new("div"),
                        children: Vec::new(),
                    });
                }
            },

            Event::End(tag_end) => match tag_end {
                TagEnd::TableHead => {
                    if let Some(Frame::Table {
                        in_head, col_index, ..
                    }) = stack.last_mut()
                    {
                        *in_head = false;
                        *col_index = 0;
                    }
                }
                TagEnd::TableRow => {
                    if let Some(Frame::Table {
                        body_rows,
                        current_row_cells,
                        col_index,
                        ..
                    }) = stack.last_mut()
                    {
                        let mut tr = VTag::new("tr");
                        tr.add_children(std::mem::take(current_row_cells));
                        body_rows.push(VNode::from(tr));
                        *col_index = 0;
                    }
                }
                _ => {
                    if stack.len() > 1 {
                        let popped = stack.pop().expect("non-empty frame stack");
                        let node = finish_frame(popped, ctx);
                        if let Some(parent) = stack.last_mut() {
                            parent.push_child(node);
                        }
                    }
                }
            },

            Event::Text(text) | Event::Html(text) | Event::InlineHtml(text) => {
                if let Some(current) = stack.last_mut() {
                    current.push_text(&text);
                }
            }

            Event::Code(code) | Event::InlineMath(code) | Event::DisplayMath(code) => {
                let mut code_tag = VTag::new("code");
                code_tag.add_child(VNode::from(VText::new(code.into_string())));
                if let Some(current) = stack.last_mut() {
                    current.push_child(VNode::from(code_tag));
                }
            }

            Event::FootnoteReference(label) => {
                let mut sup = VTag::new("sup");
                sup.add_child(VNode::from(VText::new(format!("[{label}]"))));
                if let Some(current) = stack.last_mut() {
                    current.push_child(VNode::from(sup));
                }
            }

            Event::SoftBreak => {
                if let Some(current) = stack.last_mut() {
                    current.push_text("\n");
                }
            }

            Event::HardBreak => {
                if let Some(current) = stack.last_mut() {
                    current.push_child(VNode::from(VTag::new("br")));
                }
            }

            Event::Rule => {
                if let Some(current) = stack.last_mut() {
                    current.push_child(VNode::from(VTag::new("hr")));
                }
            }

            Event::TaskListMarker(checked) => {
                mark_enclosing_list_item_as_task(&mut stack);
                let mut input = VTag::new("input");
                input.add_attribute("type", "checkbox");
                input.add_attribute("class", "task-list-item-checkbox");
                input.add_attribute("disabled", "");
                if checked {
                    input.add_attribute("checked", "");
                }
                input.set_checked(checked);
                if let Some(current) = stack.last_mut() {
                    current.push_child(VNode::from(input));
                    current.push_text(" ");
                }
            }
        }
    }

    while stack.len() > 1 {
        let popped = stack.pop().expect("non-empty frame stack");
        let node = finish_frame(popped, ctx);
        if let Some(parent) = stack.last_mut() {
            parent.push_child(node);
        }
    }

    let root_children = match stack.pop() {
        Some(Frame::Root { children }) => children,
        _ => Vec::new(),
    };

    let mut container = VTag::new("div");
    container.add_attribute("class", "markdown-body");
    container.add_children(root_children);
    VNode::from(container)
}

fn finish_frame(frame: Frame, ctx: Option<&MarkdownContext>) -> VNode {
    match frame {
        Frame::Root { children } => {
            let mut list = VList::new();
            list.add_children(children);
            VNode::from(list)
        }
        Frame::Tag { mut tag, children } => {
            tag.add_children(children);
            VNode::from(tag)
        }
        Frame::CodeBlock { language, text } => {
            let mut code_tag = VTag::new("code");
            if let Some(lang) = language {
                code_tag.add_attribute("class", format!("language-{lang}"));
            }
            code_tag.add_child(VNode::from(VText::new(text)));
            let mut pre_tag = VTag::new("pre");
            pre_tag.add_child(VNode::from(code_tag));
            VNode::from(pre_tag)
        }
        Frame::Table {
            head_cells,
            body_rows,
            ..
        } => {
            let mut table = VTag::new("table");
            if !head_cells.is_empty() {
                let mut tr = VTag::new("tr");
                tr.add_children(head_cells);
                let mut thead = VTag::new("thead");
                thead.add_child(VNode::from(tr));
                table.add_child(VNode::from(thead));
            }
            if !body_rows.is_empty() {
                let mut tbody = VTag::new("tbody");
                tbody.add_children(body_rows);
                table.add_child(VNode::from(tbody));
            }
            VNode::from(table)
        }
        Frame::TableCell {
            is_header,
            align,
            children,
        } => {
            let mut cell = VTag::new(if is_header { "th" } else { "td" });
            if let Some(alignment) = align {
                cell.add_attribute("align", alignment);
            }
            cell.add_children(children);
            VNode::from(cell)
        }
        Frame::Link {
            resolved_href,
            is_internal,
            title,
            children,
        } => {
            if let Some(href) = resolved_href {
                let nav_cb = if is_internal {
                    ctx.and_then(|c| c.on_navigate.clone())
                } else {
                    None
                };

                if let Some(cb) = nav_cb {
                    let target_route = href.clone();
                    let onclick = Callback::from(move |e: MouseEvent| {
                        if !e.ctrl_key()
                            && !e.meta_key()
                            && !e.shift_key()
                            && !e.alt_key()
                            && e.button() == 0
                        {
                            e.prevent_default();
                            cb.emit(target_route.clone());
                        }
                    });
                    let mut child_list = VList::new();
                    child_list.add_children(children);
                    if title.is_empty() {
                        html! {
                            <a href={href} onclick={onclick}>{ VNode::from(child_list) }</a>
                        }
                    } else {
                        html! {
                            <a href={href} title={title} onclick={onclick}>{ VNode::from(child_list) }</a>
                        }
                    }
                } else {
                    let mut a = VTag::new("a");
                    let is_external = href.starts_with("http://") || href.starts_with("https://");
                    a.add_attribute("href", href);
                    if !title.is_empty() {
                        a.add_attribute("title", title);
                    }
                    if is_external {
                        a.add_attribute("rel", "noopener noreferrer");
                    }
                    a.add_children(children);
                    VNode::from(a)
                }
            } else {
                let mut span = VTag::new("span");
                span.add_attribute("class", "markdown-unsafe-link");
                span.add_children(children);
                VNode::from(span)
            }
        }
        Frame::Image {
            resolved_src,
            title,
            alt_text,
        } => {
            if let Some(src) = resolved_src {
                let mut img = VTag::new("img");
                img.add_attribute("src", src);
                img.add_attribute("alt", alt_text);
                if !title.is_empty() {
                    img.add_attribute("title", title);
                }
                VNode::from(img)
            } else {
                let mut span = VTag::new("span");
                span.add_attribute("class", "markdown-unsafe-image");
                span.add_child(VNode::from(VText::new(alt_text)));
                VNode::from(span)
            }
        }
    }
}

/// Properties for the [`MarkdownView`] Yew component.
#[derive(Properties, Clone, PartialEq)]
pub struct MarkdownProps {
    pub markdown: AttrValue,
    #[prop_or_default]
    pub context: Option<MarkdownContext>,
}

/// Reusable Yew component that renders CommonMark + GFM Markdown safely into [`Html`].
#[function_component(MarkdownView)]
pub fn markdown_view(props: &MarkdownProps) -> Html {
    render_markdown(props.markdown.as_str(), props.context.as_ref())
}

/// Serializes a Yew [`VNode`] tree into an HTML string for deterministic inspection
/// and unit testing, escaping text nodes and attribute values.
#[must_use]
pub fn render_vnode_to_html_string(node: &VNode) -> String {
    let mut out = String::new();
    write_vnode_html(node, &mut out);
    out
}

fn write_vnode_html(node: &VNode, out: &mut String) {
    match node {
        VNode::VText(vtext) => push_escaped_html(vtext.text.as_str(), out),
        VNode::VList(vlist) => {
            for child in vlist.iter() {
                write_vnode_html(child, out);
            }
        }
        VNode::VTag(vtag) => {
            let tag = vtag.tag();
            out.push('<');
            out.push_str(tag);

            let mut attrs: Vec<(&str, &str)> = vtag.attributes.iter().collect();
            attrs.sort_by(|a, b| a.0.cmp(b.0));
            for (k, v) in attrs {
                out.push(' ');
                out.push_str(k);
                if !v.is_empty() || !matches!(k, "disabled" | "checked") {
                    out.push_str("=\"");
                    push_escaped_html(v, out);
                    out.push('"');
                }
            }

            if matches!(tag, "br" | "hr" | "img" | "input") {
                out.push_str(" />");
                return;
            }

            out.push('>');
            if let Some(children) = vtag.children() {
                write_vnode_html(children, out);
            }
            out.push_str("</");
            out.push_str(tag);
            out.push('>');
        }
        _ => {}
    }
}

fn push_escaped_html(s: &str, out: &mut String) {
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            other => out.push(other),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_no_vraw_or_forbidden_tags(node: &VNode, forbidden_tags: &[&str]) {
        match node {
            VNode::VRaw(_) => panic!("VRaw / from_html_unchecked must never be used"),
            VNode::VTag(vtag) => {
                let tag_name = vtag.tag();
                assert!(
                    !forbidden_tags
                        .iter()
                        .any(|t| t.eq_ignore_ascii_case(tag_name)),
                    "found forbidden VTag <{tag_name}>"
                );
                for (k, _) in vtag.attributes.iter() {
                    assert!(
                        !k.to_ascii_lowercase().starts_with("on"),
                        "found inline event handler attribute {k} on <{tag_name}>"
                    );
                }
                if let Some(children) = vtag.children() {
                    assert_no_vraw_or_forbidden_tags(children, forbidden_tags);
                }
            }
            VNode::VList(vlist) => {
                for child in vlist.iter() {
                    assert_no_vraw_or_forbidden_tags(child, forbidden_tags);
                }
            }
            _ => {}
        }
    }

    fn collect_vtags<'a>(node: &'a VNode, tag_name: &str, out: &mut Vec<&'a VTag>) {
        match node {
            VNode::VTag(vtag) => {
                if vtag.tag() == tag_name {
                    out.push(vtag);
                }
                if let Some(children) = vtag.children() {
                    collect_vtags(children, tag_name, out);
                }
            }
            VNode::VList(vlist) => {
                for child in vlist.iter() {
                    collect_vtags(child, tag_name, out);
                }
            }
            _ => {}
        }
    }

    #[test]
    fn renders_commonmark_and_gfm_elements_into_vnode_tree() {
        let md = "\
# Main Title {#main-id .hero}

Paragraph with *emphasis*, **strong**, ~~strikethrough~~, and `inline_code()`.
Line with soft break
and hard break.  
Next line.

> Blockquote line

```rust,ignore
fn main() {
    println!(\"hello <world>\");
}
```

    indented_code();

- [x] Completed task
- [ ] Pending task

3. Third item
4. Fourth item

| Feature | Status | Score | Notes |
| :--- | :---: | ---: | --- |
| Tables | Done | 100 | GFM |
| Tasks | Active | 95 | Checkboxes |

---
";
        let vnode = render_markdown(md, None);
        assert_no_vraw_or_forbidden_tags(&vnode, &["script", "iframe", "object", "embed"]);

        // Root is <div class="markdown-body">
        let VNode::VTag(root) = &vnode else {
            panic!("expected root VTag");
        };
        assert_eq!(root.tag(), "div");
        assert!(root
            .attributes
            .iter()
            .any(|(k, v)| k == "class" && v == "markdown-body"));

        // Verify task list checkboxes have checked state and disabled attribute on VTag
        let mut inputs = Vec::new();
        collect_vtags(&vnode, "input", &mut inputs);
        assert_eq!(inputs.len(), 2);
        assert_eq!(inputs[0].checked(), Some(true));
        assert!(inputs[0].attributes.iter().any(|(k, _)| k == "disabled"));
        assert!(inputs[0].attributes.iter().any(|(k, _)| k == "checked"));
        assert_eq!(inputs[1].checked(), Some(false));
        assert!(inputs[1].attributes.iter().any(|(k, _)| k == "disabled"));

        let html = render_vnode_to_html_string(&vnode);
        assert!(html.contains("<h1 class=\"hero\" id=\"main-id\">Main Title</h1>"));
        assert!(html.contains("<em>emphasis</em>"));
        assert!(html.contains("<strong>strong</strong>"));
        assert!(html.contains("<del>strikethrough</del>"));
        assert!(html.contains("<code>inline_code()</code>"));
        assert!(html.contains("<br />"));
        assert!(html.contains("<blockquote><p>Blockquote line</p></blockquote>"));
        assert!(html.contains(
            "<pre><code class=\"language-rust\">fn main() {\n    println!(&quot;hello &lt;world&gt;&quot;);\n}\n</code></pre>"
        ));
        assert!(html.contains("<pre><code>indented_code();\n</code></pre>"));
        assert!(html.contains("<li class=\"task-list-item\"><input checked class=\"task-list-item-checkbox\" disabled type=\"checkbox\" /> Completed task</li>"));
        assert!(html.contains("<li class=\"task-list-item\"><input class=\"task-list-item-checkbox\" disabled type=\"checkbox\" /> Pending task</li>"));
        assert!(html.contains("<ol start=\"3\"><li>Third item</li><li>Fourth item</li></ol>"));
        assert!(html.contains("<table><thead><tr><th align=\"left\">Feature</th><th align=\"center\">Status</th><th align=\"right\">Score</th><th>Notes</th></tr></thead><tbody><tr><td align=\"left\">Tables</td><td align=\"center\">Done</td><td align=\"right\">100</td><td>GFM</td></tr><tr><td align=\"left\">Tasks</td><td align=\"center\">Active</td><td align=\"right\">95</td><td>Checkboxes</td></tr></tbody></table>"));
        assert!(html.contains("<hr />"));
    }

    #[test]
    fn neutralizes_raw_html_and_xss_payloads_without_inner_html() {
        let payloads = [
            "<script>alert(1)</script>",
            "Hello <script>alert('xss')</script> world",
            "<img src=x onerror=alert(1)>",
            "<iframe src=\"javascript:alert(1)\"></iframe>",
            "[click](javascript:alert(1))",
            "[click](&#x6a;avascript:alert(1))",
            "[click](&#106;avascript:alert(1))",
            "[click](JaVaScRiPt:alert(1))",
            "[click](java\nscript:alert(1))",
            "[click](java\tscript:alert(1))",
            "[click](data:text/html,<script>alert(1)</script>)",
            "[click](vbscript:msgbox(1))",
            "[click](file:///etc/passwd)",
            "[click](//evil.example.com/xss)",
            "![img](javascript:alert(1))",
            "![img](data:image/svg+xml,<svg onload=alert(1)>)",
            "![img](//evil.example.com/pixel.png)",
        ];

        for payload in payloads {
            let vnode = render_markdown(payload, None);
            assert_no_vraw_or_forbidden_tags(
                &vnode,
                &["script", "iframe", "object", "embed", "svg"],
            );

            // Ensure no <a> or <img> element is ever emitted for unsafe payloads
            let mut links = Vec::new();
            collect_vtags(&vnode, "a", &mut links);
            assert!(
                links.is_empty(),
                "expected no <a> tag for payload `{payload}`, found: {links:?}"
            );

            let mut images = Vec::new();
            collect_vtags(&vnode, "img", &mut images);
            assert!(
                images.is_empty(),
                "expected no <img> tag for payload `{payload}`, found: {images:?}"
            );

            let html = render_vnode_to_html_string(&vnode);
            assert!(
                !html.contains("<script"),
                "raw <script> must be escaped for `{payload}`: {html}"
            );
            assert!(
                !html.contains("<img"),
                "raw <img> must be escaped or neutralized for `{payload}`: {html}"
            );
            assert!(
                !html.contains("<iframe"),
                "raw <iframe> must be escaped for `{payload}`: {html}"
            );
            assert!(
                !html.contains("href="),
                "unsafe href must never be emitted for `{payload}`: {html}"
            );
        }

        // Verify direct resolve_markdown_url also rejects obfuscated schemes
        for bad_url in [
            "",
            "   ",
            "javascript:alert(1)",
            "&#x6a;avascript:alert(1)",
            "&#106;avascript:alert(1)",
            "javascript&colon;alert(1)",
            "JaVaScRiPt:alert(1)",
            "java\nscript:alert(1)",
            "java\tscript:alert(1)",
            "java\0script:alert(1)",
            "data:text/html,<script>alert(1)</script>",
            "vbscript:msgbox(1)",
            "file:///etc/passwd",
            "custom-scheme:something",
            "//evil.example.com/xss",
            "\\\\evil.example.com\\xss",
            "http:///missing-host",
            "https://",
            "mailto:",
        ] {
            assert_eq!(
                resolve_markdown_url(bad_url, None, false),
                None,
                "expected link URL `{bad_url}` to be rejected"
            );
            assert_eq!(
                resolve_markdown_url(bad_url, None, true),
                None,
                "expected image URL `{bad_url}` to be rejected"
            );
            assert!(!is_safe_markdown_url(bad_url, false));
            assert!(!is_safe_markdown_url(bad_url, true));
        }

        // Verify fallback rendering of unsafe links and images preserves visible label/alt text
        let unsafe_md = "[Safe Text](javascript:alert(1)) and ![Alt Text](javascript:alert(1))";
        let html = render_vnode_to_html_string(&render_markdown(unsafe_md, None));
        assert!(html.contains("<span class=\"markdown-unsafe-link\">Safe Text</span>"));
        assert!(html.contains("<span class=\"markdown-unsafe-image\">Alt Text</span>"));
    }

    #[test]
    fn resolves_relative_links_and_images_from_root_and_nested_directories() {
        let root_ctx = MarkdownContext::new("users", "alice", "public", "dotfiles.git", "main", "");
        assert_eq!(root_ctx.repo, "dotfiles");
        assert_eq!(root_ctx.current_dir, "");

        // Root directory resolution
        assert_eq!(
            resolve_markdown_url("./sibling.md", Some(&root_ctx), false).as_deref(),
            Some("/users/alice/public/dotfiles/blob/main/sibling.md")
        );
        assert_eq!(
            resolve_markdown_url("../README.md", Some(&root_ctx), false).as_deref(),
            Some("/users/alice/public/dotfiles/blob/main/README.md")
        );
        assert_eq!(
            resolve_markdown_url("sub/dir/", Some(&root_ctx), false).as_deref(),
            Some("/users/alice/public/dotfiles/tree/main/sub/dir")
        );
        assert_eq!(
            resolve_markdown_url(".", Some(&root_ctx), false).as_deref(),
            Some("/users/alice/public/dotfiles/tree/main")
        );
        assert_eq!(
            resolve_markdown_url("#section-anchor", Some(&root_ctx), false).as_deref(),
            Some("#section-anchor")
        );
        assert_eq!(
            resolve_markdown_url("docs/setup.md#install", Some(&root_ctx), false).as_deref(),
            Some("/users/alice/public/dotfiles/blob/main/docs/setup.md#install")
        );
        assert_eq!(
            resolve_markdown_url("../../../../etc/passwd", Some(&root_ctx), false).as_deref(),
            Some("/users/alice/public/dotfiles/blob/main/etc/passwd")
        );
        assert_eq!(
            resolve_markdown_url("assets/logo.png", Some(&root_ctx), true).as_deref(),
            Some("/users/alice/public/dotfiles/blob/main/assets/logo.png")
        );

        // Nested directory (`docs/guides`) resolution
        let nested_ctx = MarkdownContext::new(
            "teams",
            "core",
            "private",
            "handbook",
            "v1.2.0",
            "docs/guides",
        );
        assert_eq!(nested_ctx.current_dir, "docs/guides");

        assert_eq!(
            resolve_markdown_url("./sibling.md", Some(&nested_ctx), false).as_deref(),
            Some("/teams/core/private/handbook/blob/v1.2.0/docs/guides/sibling.md")
        );
        assert_eq!(
            resolve_markdown_url("../README.md", Some(&nested_ctx), false).as_deref(),
            Some("/teams/core/private/handbook/blob/v1.2.0/docs/README.md")
        );
        assert_eq!(
            resolve_markdown_url("../../README.md", Some(&nested_ctx), false).as_deref(),
            Some("/teams/core/private/handbook/blob/v1.2.0/README.md")
        );
        assert_eq!(
            resolve_markdown_url("sub/dir/", Some(&nested_ctx), false).as_deref(),
            Some("/teams/core/private/handbook/tree/v1.2.0/docs/guides/sub/dir")
        );
        assert_eq!(
            resolve_markdown_url("..", Some(&nested_ctx), false).as_deref(),
            Some("/teams/core/private/handbook/tree/v1.2.0/docs")
        );
        assert_eq!(
            resolve_markdown_url("../..", Some(&nested_ctx), false).as_deref(),
            Some("/teams/core/private/handbook/tree/v1.2.0")
        );
        assert_eq!(
            resolve_markdown_url("#section-anchor", Some(&nested_ctx), false).as_deref(),
            Some("#section-anchor")
        );
        assert_eq!(
            resolve_markdown_url("setup.md#install", Some(&nested_ctx), false).as_deref(),
            Some("/teams/core/private/handbook/blob/v1.2.0/docs/guides/setup.md#install")
        );
        assert_eq!(
            resolve_markdown_url("../../../../etc/passwd", Some(&nested_ctx), false).as_deref(),
            Some("/teams/core/private/handbook/blob/v1.2.0/etc/passwd")
        );
        assert_eq!(
            resolve_markdown_url("../img/arch.svg", Some(&nested_ctx), true).as_deref(),
            Some("/teams/core/private/handbook/blob/v1.2.0/docs/img/arch.svg")
        );

        // External URLs pass through unchanged
        assert_eq!(
            resolve_markdown_url("https://example.com/guide", Some(&nested_ctx), false).as_deref(),
            Some("https://example.com/guide")
        );
        assert_eq!(
            resolve_markdown_url("http://example.com/banner.png", Some(&nested_ctx), true)
                .as_deref(),
            Some("http://example.com/banner.png")
        );
        assert_eq!(
            resolve_markdown_url("mailto:sec@example.com", Some(&nested_ctx), false).as_deref(),
            Some("mailto:sec@example.com")
        );
        // Images reject mailto: and #fragment and directories
        assert_eq!(
            resolve_markdown_url("mailto:sec@example.com", Some(&nested_ctx), true),
            None
        );
        assert_eq!(
            resolve_markdown_url("#section", Some(&nested_ctx), true),
            None
        );
        assert_eq!(
            resolve_markdown_url("sub/dir/", Some(&nested_ctx), true),
            None
        );
    }

    #[test]
    fn renders_rewritten_links_images_and_navigation_callback_in_markdown() {
        let navigated = std::rc::Rc::new(std::cell::RefCell::new(Vec::<String>::new()));
        let nav_clone = std::rc::Rc::clone(&navigated);
        let ctx = MarkdownContext::new(
            "users",
            "alice",
            "public",
            "dotfiles.git",
            "main",
            "docs/guides",
        )
        .with_on_navigate(Callback::from(move |route: String| {
            nav_clone.borrow_mut().push(route);
        }));

        let md = "\
See [Sibling](./sibling.md \"Sibling Doc\"), [Subdir](sub/dir/), [Anchor](#intro), \
[External](https://example.com \"Ext\"), and ![Diagram](../assets/flow.svg \"Flow\").";

        let vnode = render_markdown(md, Some(&ctx));
        let html = render_vnode_to_html_string(&vnode);

        assert!(html.contains(
            "<a href=\"/users/alice/public/dotfiles/blob/main/docs/guides/sibling.md\" title=\"Sibling Doc\">Sibling</a>"
        ));
        assert!(html.contains(
            "<a href=\"/users/alice/public/dotfiles/tree/main/docs/guides/sub/dir\">Subdir</a>"
        ));
        assert!(html.contains("<a href=\"#intro\">Anchor</a>"));
        assert!(html.contains(
            "<a href=\"https://example.com\" rel=\"noopener noreferrer\" title=\"Ext\">External</a>"
        ));
        assert!(html.contains(
            "<img alt=\"Diagram\" src=\"/users/alice/public/dotfiles/blob/main/docs/assets/flow.svg\" title=\"Flow\" />"
        ));
    }
}
