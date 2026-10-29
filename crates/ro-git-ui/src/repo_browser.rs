//! Repository browser routing, Protobuf decoders, pure view-model helpers,
//! and Yew HTML renderers for Tree, Blob, README, Commit Log, and Commit Diff views.

use ro_git_proto::ro_git::v1::{
    CommitFileDiffView, CommitInfoView, GetBlobResponseView, GetCommitResponseView,
    GetRepositoryResponseView, GetTreeResponseView, ListCommitsResponseView, RefInfoView,
    TreeEntryView,
};
use ro_git_proto::{
    format_blob_api_path, format_canonical_path, format_commit_api_path, format_commits_api_path,
    format_repository_api_path, format_tree_api_path, is_valid_diff_status, is_valid_identifier,
    is_valid_oid, is_valid_revision, is_valid_scope, is_valid_tree_kind, is_valid_visibility,
    normalize_repo_path as validate_proto_repo_path, normalize_revision, strip_git_suffix,
    tree_kind_from_mode, DEFAULT_REVISION, DIFF_STATUS_ADDED, DIFF_STATUS_COPIED,
    DIFF_STATUS_DELETED, DIFF_STATUS_MODIFIED, DIFF_STATUS_RENAMED, DIFF_STATUS_TYPECHANGE,
    SCOPE_TEAMS, SCOPE_USERS, TREE_KIND_DIR, TREE_KIND_FILE, TREE_KIND_SUBMODULE,
    TREE_KIND_SYMLINK, VISIBILITY_PRIVATE, VISIBILITY_PUBLIC,
};
use yew::prelude::*;

use crate::{
    copy_button_label, normalize_repo_path, CopyTarget, MarkdownContext, MarkdownProps,
    MarkdownView, RepositoryItem, DEFAULT_SSH_HOST,
};

/// Default commit log page size requested from `ListCommits`.
pub const COMMITS_PAGE_SIZE: u32 = 50;

const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";

/// Percent-encodes a single URI path segment or query parameter value (RFC 3986 unreserved set).
#[must_use]
pub fn percent_encode_component(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for &b in input.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(HEX_UPPER[(b >> 4) as usize] as char);
            out.push(HEX_UPPER[(b & 0x0f) as usize] as char);
        }
    }
    out
}

/// Percent-encodes a `/`-delimited repository-relative path while preserving `/` separators.
#[must_use]
pub fn percent_encode_path(path: &str) -> String {
    path.split('/')
        .filter(|seg| !seg.is_empty())
        .map(percent_encode_component)
        .collect::<Vec<_>>()
        .join("/")
}

#[inline]
const fn decode_hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Percent-decodes a URI path segment or query component into a UTF-8 `String`.
pub fn percent_decode_component(input: &str) -> Result<String, String> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut idx = 0;

    while idx < bytes.len() {
        if bytes[idx] == b'%' {
            if idx + 2 >= bytes.len() {
                return Err("incomplete percent-encoding sequence".to_owned());
            }
            let hi = decode_hex_nibble(bytes[idx + 1])
                .ok_or_else(|| "invalid hex digit in percent-encoding".to_owned())?;
            let lo = decode_hex_nibble(bytes[idx + 2])
                .ok_or_else(|| "invalid hex digit in percent-encoding".to_owned())?;
            out.push((hi << 4) | lo);
            idx += 3;
        } else {
            out.push(bytes[idx]);
            idx += 1;
        }
    }

    String::from_utf8(out).map_err(|_| "invalid UTF-8 in percent-decoded component".to_owned())
}

/// Builds the `GET /api/v1/repositories/{scope}/{owner}/{visibility}/{name}` request URL.
#[must_use]
pub fn build_repository_api_url(
    scope: &str,
    owner: &str,
    visibility: &str,
    name: &str,
    revision: Option<&str>,
) -> String {
    let base = format_repository_api_path(scope, owner, visibility, name);
    match revision.map(str::trim).filter(|r| !r.is_empty()) {
        Some(rev) => format!("{base}?revision={}", percent_encode_component(rev)),
        None => base,
    }
}

/// Builds the `GET /api/v1/repositories/{scope}/{owner}/{visibility}/{name}/tree` request URL.
#[must_use]
pub fn build_tree_api_url(
    scope: &str,
    owner: &str,
    visibility: &str,
    name: &str,
    revision: &str,
    path: &str,
) -> String {
    let base = format_tree_api_path(scope, owner, visibility, name);
    let rev = normalize_revision(revision);
    let clean_path = path.trim().trim_matches('/');
    if clean_path.is_empty() {
        format!("{base}?revision={}", percent_encode_component(rev))
    } else {
        format!(
            "{base}?revision={}&path={}",
            percent_encode_component(rev),
            percent_encode_component(clean_path)
        )
    }
}

/// Builds the `GET /api/v1/repositories/{scope}/{owner}/{visibility}/{name}/blob` request URL.
#[must_use]
pub fn build_blob_api_url(
    scope: &str,
    owner: &str,
    visibility: &str,
    name: &str,
    revision: &str,
    path: &str,
) -> String {
    let base = format_blob_api_path(scope, owner, visibility, name);
    let rev = normalize_revision(revision);
    let clean_path = path.trim().trim_matches('/');
    format!(
        "{base}?revision={}&path={}",
        percent_encode_component(rev),
        percent_encode_component(clean_path)
    )
}

/// Builds the `GET /api/v1/repositories/{scope}/{owner}/{visibility}/{name}/commits` request URL.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn build_commits_api_url(
    scope: &str,
    owner: &str,
    visibility: &str,
    name: &str,
    revision: &str,
    path: &str,
    limit: u32,
    offset: u32,
) -> String {
    let base = format_commits_api_path(scope, owner, visibility, name);
    let rev = normalize_revision(revision);
    let mut url = format!("{base}?revision={}", percent_encode_component(rev));
    let clean_path = path.trim().trim_matches('/');
    if !clean_path.is_empty() {
        url.push_str("&path=");
        url.push_str(&percent_encode_component(clean_path));
    }
    if limit > 0 {
        url.push_str(&format!("&limit={limit}"));
    }
    if offset > 0 {
        url.push_str(&format!("&offset={offset}"));
    }
    url
}

/// Builds the `GET /api/v1/repositories/{scope}/{owner}/{visibility}/{name}/commit` request URL.
#[must_use]
pub fn build_commit_api_url(
    scope: &str,
    owner: &str,
    visibility: &str,
    name: &str,
    revision: &str,
) -> String {
    let base = format_commit_api_path(scope, owner, visibility, name);
    let rev = normalize_revision(revision);
    format!("{base}?revision={}", percent_encode_component(rev))
}

/// Validated 4-segment repository coordinates (`scope`, `owner`, `visibility`, `name`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoCoordinates {
    pub scope: String,
    pub owner: String,
    pub visibility: String,
    pub name: String,
}

impl RepoCoordinates {
    /// Validates and constructs [`RepoCoordinates`], stripping an optional `.git` suffix from `name`.
    #[must_use]
    pub fn new(scope: &str, owner: &str, visibility: &str, name: &str) -> Option<Self> {
        let s = scope.trim();
        let o = owner.trim();
        let v = visibility.trim();
        let n = strip_git_suffix(name.trim());
        if !is_valid_scope(s)
            || !is_valid_identifier(o)
            || !is_valid_visibility(v)
            || !is_valid_identifier(n)
        {
            return None;
        }
        Some(Self {
            scope: s.to_owned(),
            owner: o.to_owned(),
            visibility: v.to_owned(),
            name: n.to_owned(),
        })
    }

    /// Formats the canonical repository path (`/<scope>/<owner>/<visibility>/<name>.git`).
    #[must_use]
    pub fn canonical_path(&self) -> String {
        format_canonical_path(&self.scope, &self.owner, &self.visibility, &self.name)
    }

    /// Formats the human-readable `scope / owner / visibility / name` title.
    #[must_use]
    pub fn display_title(&self) -> String {
        format!(
            "{} / {} / {} / {}",
            self.scope, self.owner, self.visibility, self.name
        )
    }

    /// Returns the singular scope badge (`"user"` or `"team"`).
    #[must_use]
    pub fn scope_badge(&self) -> &'static str {
        if self.scope == SCOPE_USERS {
            "user"
        } else if self.scope == SCOPE_TEAMS {
            "team"
        } else {
            "repo"
        }
    }

    /// Returns the visibility badge (`"public"` or `"private"`).
    #[must_use]
    pub fn visibility_badge(&self) -> &'static str {
        if self.visibility == VISIBILITY_PRIVATE {
            VISIBILITY_PRIVATE
        } else {
            VISIBILITY_PUBLIC
        }
    }

    /// Formats the repository overview route (`/{scope}/{owner}/{visibility}/{name}`).
    #[must_use]
    pub fn root_route(&self) -> String {
        format!(
            "/{}/{}/{}/{}",
            self.scope, self.owner, self.visibility, self.name
        )
    }

    /// Formats the directory tree route (`/{scope}/{owner}/{visibility}/{name}/tree/{revision}[/{path}]`).
    #[must_use]
    pub fn tree_route(&self, revision: &str, path: &str) -> String {
        let rev = percent_encode_component(normalize_revision(revision));
        let clean_path = percent_encode_path(path);
        if clean_path.is_empty() {
            format!("{}/tree/{rev}", self.root_route())
        } else {
            format!("{}/tree/{rev}/{clean_path}", self.root_route())
        }
    }

    /// Formats the blob view route (`/{scope}/{owner}/{visibility}/{name}/blob/{revision}/{path}`).
    #[must_use]
    pub fn blob_route(&self, revision: &str, path: &str) -> String {
        let clean_path = percent_encode_path(path);
        if clean_path.is_empty() {
            self.tree_route(revision, "")
        } else {
            let rev = percent_encode_component(normalize_revision(revision));
            format!("{}/blob/{rev}/{clean_path}", self.root_route())
        }
    }

    /// Formats the commit log route (`/{scope}/{owner}/{visibility}/{name}/commits[/{revision}[/{path}]][?offset=N]`).
    #[must_use]
    pub fn commits_route(&self, revision: &str, path: &str, offset: u32) -> String {
        let rev_trimmed = revision.trim();
        let clean_path = percent_encode_path(path);
        let mut route = if rev_trimmed.is_empty() && clean_path.is_empty() {
            format!("{}/commits", self.root_route())
        } else {
            let rev = percent_encode_component(normalize_revision(rev_trimmed));
            if clean_path.is_empty() {
                format!("{}/commits/{rev}", self.root_route())
            } else {
                format!("{}/commits/{rev}/{clean_path}", self.root_route())
            }
        };
        if offset > 0 {
            route.push_str(&format!("?offset={offset}"));
        }
        route
    }

    /// Formats the individual commit detail route (`/{scope}/{owner}/{visibility}/{name}/commit/{revision}`).
    #[must_use]
    pub fn commit_route(&self, revision: &str) -> String {
        let rev = percent_encode_component(normalize_revision(revision));
        format!("{}/commit/{rev}", self.root_route())
    }
}

/// Client-side SPA route representation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum AppRoute {
    #[default]
    Index,
    RepoRoot {
        repo: RepoCoordinates,
    },
    Tree {
        repo: RepoCoordinates,
        revision: String,
        path: String,
    },
    Blob {
        repo: RepoCoordinates,
        revision: String,
        path: String,
    },
    Commits {
        repo: RepoCoordinates,
        revision: String,
        path: String,
        offset: u32,
    },
    CommitDetail {
        repo: RepoCoordinates,
        revision: String,
    },
}

impl AppRoute {
    /// Parses a browser pathname (with optional `?query` and `#fragment`) into an [`AppRoute`].
    #[must_use]
    pub fn parse(raw_url: &str) -> Option<Self> {
        let without_fragment = raw_url.trim().split('#').next().unwrap_or("");
        let (path_part, query_opt) = match without_fragment.split_once('?') {
            Some((p, q)) => (p, Some(q)),
            None => (without_fragment, None),
        };

        let raw_segments: Vec<&str> = path_part
            .split('/')
            .filter(|seg| !seg.is_empty())
            .collect();

        if raw_segments.is_empty() {
            return Some(Self::Index);
        }
        if raw_segments.len() < 4 {
            return None;
        }

        let scope = percent_decode_component(raw_segments[0]).ok()?;
        let owner = percent_decode_component(raw_segments[1]).ok()?;
        let visibility = percent_decode_component(raw_segments[2]).ok()?;
        let name = percent_decode_component(raw_segments[3]).ok()?;
        let repo = RepoCoordinates::new(&scope, &owner, &visibility, &name)?;

        if raw_segments.len() == 4 {
            return Some(Self::RepoRoot { repo });
        }

        let action = percent_decode_component(raw_segments[4]).ok()?;
        match action.as_str() {
            "tree" => {
                let revision = if raw_segments.len() >= 6 {
                    percent_decode_component(raw_segments[5]).ok()?
                } else {
                    DEFAULT_REVISION.to_owned()
                };
                if !is_valid_revision(&revision) {
                    return None;
                }
                let path = decode_remaining_repo_path(&raw_segments[6..])?;
                Some(Self::Tree {
                    repo,
                    revision,
                    path,
                })
            }
            "blob" => {
                if raw_segments.len() < 7 {
                    return None;
                }
                let revision = percent_decode_component(raw_segments[5]).ok()?;
                if !is_valid_revision(&revision) {
                    return None;
                }
                let path = decode_remaining_repo_path(&raw_segments[6..])?;
                if path.is_empty() {
                    return None;
                }
                Some(Self::Blob {
                    repo,
                    revision,
                    path,
                })
            }
            "commits" => {
                let (mut revision, mut path) = if raw_segments.len() >= 6 {
                    let rev = percent_decode_component(raw_segments[5]).ok()?;
                    let p = decode_remaining_repo_path(&raw_segments[6..])?;
                    (rev, p)
                } else {
                    (DEFAULT_REVISION.to_owned(), String::new())
                };
                let mut offset = 0u32;

                if let Some(query) = query_opt {
                    for pair in query.split('&').filter(|s| !s.is_empty()) {
                        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
                        match k {
                            "revision" if raw_segments.len() < 6 && !v.is_empty() => {
                                revision = percent_decode_component(v).ok()?;
                            }
                            "path" if path.is_empty() && !v.is_empty() => {
                                let decoded = percent_decode_component(v).ok()?;
                                path = validate_proto_repo_path(&decoded)?;
                            }
                            "offset" if !v.is_empty() => {
                                let decoded = percent_decode_component(v).ok()?;
                                offset = decoded.parse::<u32>().ok()?;
                            }
                            _ => {}
                        }
                    }
                }

                if !is_valid_revision(&revision) {
                    return None;
                }
                Some(Self::Commits {
                    repo,
                    revision,
                    path,
                    offset,
                })
            }
            "commit" => {
                if raw_segments.len() != 6 {
                    return None;
                }
                let revision = percent_decode_component(raw_segments[5]).ok()?;
                if !is_valid_revision(&revision) {
                    return None;
                }
                Some(Self::CommitDetail { repo, revision })
            }
            _ => None,
        }
    }

    /// Formats the canonical browser URL path (and optional query string) for this route.
    #[must_use]
    pub fn to_path(&self) -> String {
        match self {
            Self::Index => "/".to_owned(),
            Self::RepoRoot { repo } => repo.root_route(),
            Self::Tree {
                repo,
                revision,
                path,
            } => repo.tree_route(revision, path),
            Self::Blob {
                repo,
                revision,
                path,
            } => repo.blob_route(revision, path),
            Self::Commits {
                repo,
                revision,
                path,
                offset,
            } => repo.commits_route(revision, path, *offset),
            Self::CommitDetail { repo, revision } => repo.commit_route(revision),
        }
    }

    /// Returns the [`RepoCoordinates`] if this route targets a repository.
    #[must_use]
    pub const fn repo(&self) -> Option<&RepoCoordinates> {
        match self {
            Self::Index => None,
            Self::RepoRoot { repo }
            | Self::Tree { repo, .. }
            | Self::Blob { repo, .. }
            | Self::Commits { repo, .. }
            | Self::CommitDetail { repo, .. } => Some(repo),
        }
    }

    /// Returns the explicit revision on this route, if any.
    #[must_use]
    pub fn active_revision(&self) -> Option<&str> {
        match self {
            Self::Index | Self::RepoRoot { .. } => None,
            Self::Tree { revision, .. }
            | Self::Blob { revision, .. }
            | Self::Commits { revision, .. }
            | Self::CommitDetail { revision, .. } => Some(revision.as_str()),
        }
    }

    /// Returns `true` when the active view belongs to the `Commits` tab (`Commits` or `CommitDetail`).
    #[must_use]
    pub const fn is_commits_tab(&self) -> bool {
        matches!(self, Self::Commits { .. } | Self::CommitDetail { .. })
    }

    /// Returns a new [`AppRoute`] updated to inspect `new_revision` (preserving the current view and path).
    #[must_use]
    pub fn with_revision(&self, new_revision: &str) -> Self {
        let rev = normalize_revision(new_revision).to_owned();
        match self {
            Self::Index => Self::Index,
            Self::RepoRoot { repo } => Self::Tree {
                repo: repo.clone(),
                revision: rev,
                path: String::new(),
            },
            Self::Tree { repo, path, .. } => Self::Tree {
                repo: repo.clone(),
                revision: rev,
                path: path.clone(),
            },
            Self::Blob { repo, path, .. } => Self::Blob {
                repo: repo.clone(),
                revision: rev,
                path: path.clone(),
            },
            Self::Commits { repo, path, .. } => Self::Commits {
                repo: repo.clone(),
                revision: rev,
                path: path.clone(),
                offset: 0,
            },
            Self::CommitDetail { repo, .. } => Self::Tree {
                repo: repo.clone(),
                revision: rev,
                path: String::new(),
            },
        }
    }
}

fn decode_remaining_repo_path(segments: &[&str]) -> Option<String> {
    if segments.is_empty() {
        return Some(String::new());
    }
    let mut decoded_parts = Vec::with_capacity(segments.len());
    for &seg in segments {
        let dec = percent_decode_component(seg).ok()?;
        if dec.is_empty() || dec == "." || dec == ".." || dec.contains('/') || dec.contains('\\') {
            return None;
        }
        decoded_parts.push(dec);
    }
    validate_proto_repo_path(&decoded_parts.join("/"))
}

/// Parses a client-side route string into an [`AppRoute`].
#[must_use]
pub fn parse_app_route(raw_url: &str) -> Option<AppRoute> {
    AppRoute::parse(raw_url)
}

/// Formats an [`AppRoute`] into its canonical client-side URL path.
#[must_use]
pub fn format_app_route(route: &AppRoute) -> String {
    route.to_path()
}

/// Returns the first 7 characters of a Git object SHA-1 (or the trimmed input if shorter).
#[inline]
#[must_use]
pub fn short_oid_str(oid: &str) -> &str {
    let trimmed = oid.trim();
    if is_valid_oid(trimmed) || trimmed.len() >= 7 {
        &trimmed[..7]
    } else {
        trimmed
    }
}

/// Formats a byte count into a human-readable size string (`"512 B"`, `"1.5 KiB"`, `"2.0 MiB"`).
#[must_use]
pub fn format_byte_size(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * 1024;
    const GIB: u64 = 1024 * 1024 * 1024;

    if bytes < KIB {
        format!("{bytes} B")
    } else if bytes < MIB {
        let tenths = (bytes * 10) / KIB;
        format!("{}.{} KiB", tenths / 10, tenths % 10)
    } else if bytes < GIB {
        let tenths = (bytes * 10) / MIB;
        format!("{}.{} MiB", tenths / 10, tenths % 10)
    } else {
        let tenths = (bytes * 10) / GIB;
        format!("{}.{} GiB", tenths / 10, tenths % 10)
    }
}

/// Formats a UNIX timestamp in seconds into `"YYYY-MM-DD HH:MM UTC"`.
#[must_use]
pub fn format_unix_timestamp(unix_secs: i64) -> String {
    let secs = unix_secs.max(0);
    let days = secs.div_euclid(86_400);
    let rem_secs = secs.rem_euclid(86_400);
    let hour = rem_secs / 3_600;
    let minute = (rem_secs % 3_600) / 60;

    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm)
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };

    format!("{year:04}-{m:02}-{d:02} {hour:02}:{minute:02} UTC")
}

/// Returns the parent directory of a repository-relative path (`""` when at the root).
#[must_use]
pub fn parent_dir_path(path: &str) -> String {
    let norm = normalize_repo_path("", path);
    match norm.rsplit_once('/') {
        Some((parent, _)) => parent.to_owned(),
        None => String::new(),
    }
}

/// Returns `true` if `path` has a `.md` or `.markdown` extension (case-insensitively).
#[must_use]
pub fn is_markdown_path(path: &str) -> bool {
    let trimmed = path.trim().trim_end_matches('/');
    let file_name = trimmed.rsplit('/').next().unwrap_or(trimmed);
    let Some((stem, ext)) = file_name.rsplit_once('.') else {
        return false;
    };
    !stem.is_empty() && (ext.eq_ignore_ascii_case("md") || ext.eq_ignore_ascii_case("markdown"))
}

/// Splits source code text into lines for line-numbered display, stripping trailing `\r`.
#[must_use]
pub fn split_source_lines(text: &str) -> Vec<&str> {
    if text.is_empty() {
        return Vec::new();
    }
    let mut lines: Vec<&str> = text
        .split('\n')
        .map(|l| l.strip_suffix('\r').unwrap_or(l))
        .collect();
    if text.ends_with('\n') && lines.last() == Some(&"") {
        lines.pop();
    }
    lines
}

/// Classification of a single line in a unified diff patch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffLineKind {
    Header,
    Hunk,
    Addition,
    Deletion,
    Context,
}

impl DiffLineKind {
    /// Returns the CSS class name corresponding to this diff line classification.
    #[must_use]
    pub const fn css_class(self) -> &'static str {
        match self {
            Self::Header => "diff-line-header",
            Self::Hunk => "diff-line-hunk",
            Self::Addition => "diff-line-add",
            Self::Deletion => "diff-line-del",
            Self::Context => "diff-line-ctx",
        }
    }
}

/// Classifies a single line from a unified diff patch.
#[must_use]
pub fn classify_diff_line(line: &str) -> DiffLineKind {
    if line.starts_with("@@") {
        DiffLineKind::Hunk
    } else if line.starts_with("diff --git")
        || line.starts_with("index ")
        || line.starts_with("--- ")
        || line.starts_with("+++ ")
        || line.starts_with("new file ")
        || line.starts_with("deleted file ")
        || line.starts_with("similarity index ")
        || line.starts_with("rename from ")
        || line.starts_with("rename to ")
        || line.starts_with("copy from ")
        || line.starts_with("copy to ")
        || line.starts_with("Binary files ")
    {
        DiffLineKind::Header
    } else if line.starts_with('+') {
        DiffLineKind::Addition
    } else if line.starts_with('-') {
        DiffLineKind::Deletion
    } else {
        DiffLineKind::Context
    }
}

/// Toggle mode for viewing Markdown blobs (`Rendered` vs. `Raw`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum BlobViewMode {
    #[default]
    Rendered,
    Raw,
}

/// Clickable path breadcrumb item for Tree and Blob views.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BreadcrumbItem {
    pub label: String,
    pub path: String,
    pub route: String,
    pub is_last: bool,
}

/// Generates clickable breadcrumb segments from the repository root down to `path`.
#[must_use]
pub fn build_path_breadcrumbs(
    repo: &RepoCoordinates,
    revision: &str,
    path: &str,
    leaf_is_blob: bool,
) -> Vec<BreadcrumbItem> {
    let norm = normalize_repo_path("", path);
    let segments: Vec<&str> = norm.split('/').filter(|s| !s.is_empty()).collect();
    let mut items = Vec::with_capacity(segments.len() + 1);

    items.push(BreadcrumbItem {
        label: repo.name.clone(),
        path: String::new(),
        route: repo.tree_route(revision, ""),
        is_last: segments.is_empty(),
    });

    let mut accum = String::new();
    for (idx, seg) in segments.iter().enumerate() {
        if !accum.is_empty() {
            accum.push('/');
        }
        accum.push_str(seg);
        let is_last = idx + 1 == segments.len();
        let route = if is_last && leaf_is_blob {
            repo.blob_route(revision, &accum)
        } else {
            repo.tree_route(revision, &accum)
        };
        items.push(BreadcrumbItem {
            label: (*seg).to_owned(),
            path: accum.clone(),
            route,
            is_last,
        });
    }

    items
}

/// Owned UI model for a Git branch or tag reference (`RefInfo`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefInfoModel {
    pub name: String,
    pub full_name: String,
    pub oid: String,
}

impl RefInfoModel {
    /// Returns the 7-character short OID for this reference.
    #[must_use]
    pub fn short_oid(&self) -> &str {
        short_oid_str(&self.oid)
    }

    /// Returns `true` if `full_name` is under `refs/heads/`.
    #[must_use]
    pub fn is_branch(&self) -> bool {
        self.full_name.starts_with("refs/heads/")
    }

    /// Returns `true` if `full_name` is under `refs/tags/`.
    #[must_use]
    pub fn is_tag(&self) -> bool {
        self.full_name.starts_with("refs/tags/")
    }
}

/// Owned UI model for a Git directory tree entry (`TreeEntry`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeEntryModel {
    pub mode: String,
    pub kind: String,
    pub name: String,
    pub path: String,
    pub oid: String,
    pub size: u64,
}

impl TreeEntryModel {
    /// Returns `true` if this entry is a directory (`"dir"`).
    #[must_use]
    pub fn is_dir(&self) -> bool {
        self.kind == TREE_KIND_DIR
    }

    /// Returns `true` if this entry is a regular file (`"file"`).
    #[must_use]
    pub fn is_file(&self) -> bool {
        self.kind == TREE_KIND_FILE
    }

    /// Returns `true` if this entry is a symbolic link (`"symlink"`).
    #[must_use]
    pub fn is_symlink(&self) -> bool {
        self.kind == TREE_KIND_SYMLINK
    }

    /// Returns `true` if this entry is a Git submodule (`"submodule"`).
    #[must_use]
    pub fn is_submodule(&self) -> bool {
        self.kind == TREE_KIND_SUBMODULE
    }

    /// Returns the 7-character short OID.
    #[must_use]
    pub fn short_oid(&self) -> &str {
        short_oid_str(&self.oid)
    }

    /// Formats the entry size (`"—"` for directories and submodules, human-readable bytes otherwise).
    #[must_use]
    pub fn formatted_size(&self) -> String {
        if self.is_dir() || self.is_submodule() {
            "—".to_owned()
        } else {
            format_byte_size(self.size)
        }
    }
}

/// Finds a `README.md` / `readme.md` / `README.markdown` file entry in `entries`.
#[must_use]
pub fn find_readme_entry(entries: &[TreeEntryModel]) -> Option<&TreeEntryModel> {
    if let Some(exact) = entries
        .iter()
        .find(|e| e.kind == TREE_KIND_FILE && e.name == "README.md")
    {
        return Some(exact);
    }
    if let Some(ci_md) = entries
        .iter()
        .find(|e| e.kind == TREE_KIND_FILE && e.name.eq_ignore_ascii_case("readme.md"))
    {
        return Some(ci_md);
    }
    entries
        .iter()
        .find(|e| e.kind == TREE_KIND_FILE && e.name.eq_ignore_ascii_case("readme.markdown"))
}

/// Owned UI model decoded from `GetRepositoryResponse`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepositoryOverviewModel {
    pub repository: RepositoryItem,
    pub head_ref: String,
    pub head_oid: String,
    pub resolved_revision: String,
    pub branches: Vec<RefInfoModel>,
    pub tags: Vec<RefInfoModel>,
    pub entries: Vec<TreeEntryModel>,
}

impl RepositoryOverviewModel {
    /// Returns `true` when the repository is empty/unborn (`head_oid` is empty and `entries` is empty).
    #[must_use]
    pub fn is_empty_unborn(&self) -> bool {
        self.head_oid.trim().is_empty() && self.entries.is_empty()
    }

    /// Returns the effective active revision name (`resolved_revision`, `head_ref`, or `"HEAD"`).
    #[must_use]
    pub fn effective_revision(&self) -> &str {
        if !self.resolved_revision.trim().is_empty() {
            self.resolved_revision.trim()
        } else if !self.head_ref.trim().is_empty() {
            self.head_ref.trim()
        } else {
            DEFAULT_REVISION
        }
    }
}

/// Owned UI model decoded from `GetTreeResponse`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeViewModel {
    pub revision: String,
    pub tree_oid: String,
    pub path: String,
    pub entries: Vec<TreeEntryModel>,
}

/// Owned UI model decoded from `GetBlobResponse`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobViewModel {
    pub revision: String,
    pub path: String,
    pub oid: String,
    pub size: u64,
    pub is_binary: bool,
    pub truncated: bool,
    pub content: Vec<u8>,
}

impl BlobViewModel {
    /// Returns the UTF-8 decoded blob content (substituting replacement characters for invalid sequences).
    #[must_use]
    pub fn text_lossy(&self) -> String {
        String::from_utf8_lossy(&self.content).into_owned()
    }

    /// Returns the 7-character short OID.
    #[must_use]
    pub fn short_oid(&self) -> &str {
        short_oid_str(&self.oid)
    }

    /// Formats the blob size in bytes.
    #[must_use]
    pub fn formatted_size(&self) -> String {
        format_byte_size(self.size)
    }

    /// Returns `true` if this blob is a non-binary Markdown file (`.md` or `.markdown`).
    #[must_use]
    pub fn is_markdown(&self) -> bool {
        !self.is_binary && is_markdown_path(&self.path)
    }

    /// Returns the repository-relative parent directory of this blob.
    #[must_use]
    pub fn parent_dir(&self) -> String {
        parent_dir_path(&self.path)
    }
}

/// Owned UI model decoded from `CommitInfo`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitInfoModel {
    pub oid: String,
    pub parent_oids: Vec<String>,
    pub author_name: String,
    pub author_email: String,
    pub author_time_secs: i64,
    pub committer_name: String,
    pub committer_email: String,
    pub committer_time_secs: i64,
    pub subject: String,
    pub message: String,
}

impl CommitInfoModel {
    /// Returns the 7-character short commit OID.
    #[must_use]
    pub fn short_oid(&self) -> &str {
        short_oid_str(&self.oid)
    }

    /// Returns the multi-line commit message body following the subject line (trimmed).
    #[must_use]
    pub fn body(&self) -> &str {
        let msg = self.message.trim();
        let rest = match msg.strip_prefix(self.subject.trim()) {
            Some(r) => r,
            None => match msg.split_once('\n') {
                Some((_, after)) => after,
                None => "",
            },
        };
        rest.trim()
    }
}

/// Owned UI model decoded from `CommitFileDiff`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitFileDiffModel {
    pub path: String,
    pub old_path: String,
    pub status: String,
    pub additions: u32,
    pub deletions: u32,
    pub patch: String,
}

impl CommitFileDiffModel {
    /// Formats the file header path (`"old_path -> path"` for renamed/copied files, or `"path"`).
    #[must_use]
    pub fn display_path(&self) -> String {
        if matches!(
            self.status.as_str(),
            DIFF_STATUS_RENAMED | DIFF_STATUS_COPIED
        ) && !self.old_path.is_empty()
            && self.old_path != self.path
        {
            format!("{} -> {}", self.old_path, self.path)
        } else {
            self.path.clone()
        }
    }
}

/// Owned UI model decoded from `ListCommitsResponse`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitListModel {
    pub revision: String,
    pub commits: Vec<CommitInfoModel>,
    pub has_more: bool,
}

/// Owned UI model decoded from `GetCommitResponse`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitDetailModel {
    pub commit: CommitInfoModel,
    pub files: Vec<CommitFileDiffModel>,
    pub total_additions: u32,
    pub total_deletions: u32,
    pub patch: String,
}

/// Decodes a `RefInfoView` into an owned [`RefInfoModel`].
pub fn decode_ref_info_view(view: RefInfoView<'_>) -> Result<RefInfoModel, String> {
    let name = view
        .name()
        .map_err(|e| format!("invalid RefInfo.name: {e:?}"))?
        .trim()
        .to_owned();
    let full_name = view
        .full_name()
        .map_err(|e| format!("invalid RefInfo.full_name: {e:?}"))?
        .trim()
        .to_owned();
    let oid = view
        .oid()
        .map_err(|e| format!("invalid RefInfo.oid: {e:?}"))?
        .trim()
        .to_owned();
    Ok(RefInfoModel {
        name,
        full_name,
        oid,
    })
}

/// Decodes a `TreeEntryView` into an owned [`TreeEntryModel`].
pub fn decode_tree_entry_view(view: TreeEntryView<'_>) -> Result<TreeEntryModel, String> {
    let mode = view
        .mode()
        .map_err(|e| format!("invalid TreeEntry.mode: {e:?}"))?
        .trim()
        .to_owned();
    let raw_kind = view
        .kind()
        .map_err(|e| format!("invalid TreeEntry.kind: {e:?}"))?
        .trim();
    let kind = if is_valid_tree_kind(raw_kind) {
        raw_kind.to_owned()
    } else {
        tree_kind_from_mode(&mode)
            .unwrap_or(TREE_KIND_FILE)
            .to_owned()
    };
    let name = view
        .name()
        .map_err(|e| format!("invalid TreeEntry.name: {e:?}"))?
        .to_owned();
    let path = view
        .path()
        .map_err(|e| format!("invalid TreeEntry.path: {e:?}"))?
        .trim_matches('/')
        .to_owned();
    let oid = view
        .oid()
        .map_err(|e| format!("invalid TreeEntry.oid: {e:?}"))?
        .trim()
        .to_owned();
    let size = view
        .size()
        .map_err(|e| format!("invalid TreeEntry.size: {e:?}"))?;

    Ok(TreeEntryModel {
        mode,
        kind,
        name,
        path,
        oid,
        size,
    })
}

/// Decodes a `CommitInfoView` into an owned [`CommitInfoModel`].
pub fn decode_commit_info_view(view: CommitInfoView<'_>) -> Result<CommitInfoModel, String> {
    let oid = view
        .oid()
        .map_err(|e| format!("invalid CommitInfo.oid: {e:?}"))?
        .trim()
        .to_owned();
    let mut parent_oids = Vec::new();
    for entry in view.parent_oids() {
        let p = entry.map_err(|e| format!("invalid CommitInfo.parent_oids entry: {e:?}"))?;
        let trimmed = p.trim();
        if !trimmed.is_empty() {
            parent_oids.push(trimmed.to_owned());
        }
    }
    let author_name = view
        .author_name()
        .map_err(|e| format!("invalid CommitInfo.author_name: {e:?}"))?
        .to_owned();
    let author_email = view
        .author_email()
        .map_err(|e| format!("invalid CommitInfo.author_email: {e:?}"))?
        .to_owned();
    let author_time_secs = view
        .author_time_secs()
        .map_err(|e| format!("invalid CommitInfo.author_time_secs: {e:?}"))?;
    let committer_name = view
        .committer_name()
        .map_err(|e| format!("invalid CommitInfo.committer_name: {e:?}"))?
        .to_owned();
    let committer_email = view
        .committer_email()
        .map_err(|e| format!("invalid CommitInfo.committer_email: {e:?}"))?
        .to_owned();
    let committer_time_secs = view
        .committer_time_secs()
        .map_err(|e| format!("invalid CommitInfo.committer_time_secs: {e:?}"))?;
    let subject = view
        .subject()
        .map_err(|e| format!("invalid CommitInfo.subject: {e:?}"))?
        .to_owned();
    let message = view
        .message()
        .map_err(|e| format!("invalid CommitInfo.message: {e:?}"))?
        .to_owned();

    Ok(CommitInfoModel {
        oid,
        parent_oids,
        author_name,
        author_email,
        author_time_secs,
        committer_name,
        committer_email,
        committer_time_secs,
        subject,
        message,
    })
}

/// Decodes a `CommitFileDiffView` into an owned [`CommitFileDiffModel`].
pub fn decode_commit_file_diff_view(
    view: CommitFileDiffView<'_>,
) -> Result<CommitFileDiffModel, String> {
    let path = view
        .path()
        .map_err(|e| format!("invalid CommitFileDiff.path: {e:?}"))?
        .to_owned();
    let old_path = view
        .old_path()
        .map_err(|e| format!("invalid CommitFileDiff.old_path: {e:?}"))?
        .to_owned();
    let raw_status = view
        .status()
        .map_err(|e| format!("invalid CommitFileDiff.status: {e:?}"))?
        .trim();
    let status = if is_valid_diff_status(raw_status) {
        raw_status.to_owned()
    } else {
        DIFF_STATUS_MODIFIED.to_owned()
    };
    let additions = view
        .additions()
        .map_err(|e| format!("invalid CommitFileDiff.additions: {e:?}"))?;
    let deletions = view
        .deletions()
        .map_err(|e| format!("invalid CommitFileDiff.deletions: {e:?}"))?;
    let patch = view
        .patch()
        .map_err(|e| format!("invalid CommitFileDiff.patch: {e:?}"))?
        .to_owned();

    Ok(CommitFileDiffModel {
        path,
        old_path,
        status,
        additions,
        deletions,
        patch,
    })
}

/// Decodes raw Protobuf bytes from `GetRepository` into a [`RepositoryOverviewModel`].
pub fn decode_get_repository_response(bytes: &[u8]) -> Result<RepositoryOverviewModel, String> {
    let view = GetRepositoryResponseView::from_bytes(bytes)
        .map_err(|e| format!("failed to decode GetRepositoryResponse: {e:?}"))?;
    let repo_view = view
        .repository()
        .map_err(|e| format!("invalid repository field: {e:?}"))?
        .ok_or_else(|| "missing repository field in GetRepositoryResponse".to_owned())?;

    let scope = repo_view
        .scope()
        .map_err(|e| format!("invalid repository.scope: {e:?}"))?;
    let owner = repo_view
        .owner()
        .map_err(|e| format!("invalid repository.owner: {e:?}"))?;
    let visibility = repo_view
        .visibility()
        .map_err(|e| format!("invalid repository.visibility: {e:?}"))?;
    let name = repo_view
        .name()
        .map_err(|e| format!("invalid repository.name: {e:?}"))?;
    let canonical_path = repo_view
        .canonical_path()
        .map_err(|e| format!("invalid repository.canonical_path: {e:?}"))?
        .trim();
    let ssh_url = repo_view
        .ssh_url()
        .map_err(|e| format!("invalid repository.ssh_url: {e:?}"))?
        .trim();
    let clone_command = repo_view
        .clone_command()
        .map_err(|e| format!("invalid repository.clone_command: {e:?}"))?
        .trim();

    let mut repository =
        RepositoryItem::new(DEFAULT_SSH_HOST, None, scope, owner, visibility, name);
    if !canonical_path.is_empty() {
        repository.canonical_path = canonical_path.to_owned();
    }
    if !ssh_url.is_empty() {
        repository.ssh_url = ssh_url.to_owned();
    }
    if !clone_command.is_empty() {
        repository.clone_command = clone_command.to_owned();
    }

    let head_ref = view
        .head_ref()
        .map_err(|e| format!("invalid head_ref: {e:?}"))?
        .trim()
        .to_owned();
    let head_oid = view
        .head_oid()
        .map_err(|e| format!("invalid head_oid: {e:?}"))?
        .trim()
        .to_owned();
    let resolved_revision = view
        .resolved_revision()
        .map_err(|e| format!("invalid resolved_revision: {e:?}"))?
        .trim()
        .to_owned();

    let mut branches = Vec::new();
    for item in view.branches() {
        let ref_view = item.map_err(|e| format!("invalid branches entry: {e:?}"))?;
        branches.push(decode_ref_info_view(ref_view)?);
    }

    let mut tags = Vec::new();
    for item in view.tags() {
        let ref_view = item.map_err(|e| format!("invalid tags entry: {e:?}"))?;
        tags.push(decode_ref_info_view(ref_view)?);
    }

    let mut entries = Vec::new();
    for item in view.entries() {
        let entry_view = item.map_err(|e| format!("invalid entries item: {e:?}"))?;
        entries.push(decode_tree_entry_view(entry_view)?);
    }

    Ok(RepositoryOverviewModel {
        repository,
        head_ref,
        head_oid,
        resolved_revision,
        branches,
        tags,
        entries,
    })
}

/// Decodes raw Protobuf bytes from `GetTree` into a [`TreeViewModel`].
pub fn decode_get_tree_response(bytes: &[u8]) -> Result<TreeViewModel, String> {
    let view = GetTreeResponseView::from_bytes(bytes)
        .map_err(|e| format!("failed to decode GetTreeResponse: {e:?}"))?;
    let revision = view
        .revision()
        .map_err(|e| format!("invalid revision: {e:?}"))?
        .trim()
        .to_owned();
    let tree_oid = view
        .tree_oid()
        .map_err(|e| format!("invalid tree_oid: {e:?}"))?
        .trim()
        .to_owned();
    let path = view
        .path()
        .map_err(|e| format!("invalid path: {e:?}"))?
        .trim_matches('/')
        .to_owned();

    let mut entries = Vec::new();
    for item in view.entries() {
        let entry_view = item.map_err(|e| format!("invalid TreeEntry: {e:?}"))?;
        entries.push(decode_tree_entry_view(entry_view)?);
    }

    Ok(TreeViewModel {
        revision,
        tree_oid,
        path,
        entries,
    })
}

/// Decodes raw Protobuf bytes from `GetBlob` into a [`BlobViewModel`].
pub fn decode_get_blob_response(bytes: &[u8]) -> Result<BlobViewModel, String> {
    let view = GetBlobResponseView::from_bytes(bytes)
        .map_err(|e| format!("failed to decode GetBlobResponse: {e:?}"))?;
    let revision = view
        .revision()
        .map_err(|e| format!("invalid revision: {e:?}"))?
        .trim()
        .to_owned();
    let path = view
        .path()
        .map_err(|e| format!("invalid path: {e:?}"))?
        .trim_matches('/')
        .to_owned();
    let oid = view
        .oid()
        .map_err(|e| format!("invalid oid: {e:?}"))?
        .trim()
        .to_owned();
    let size = view
        .size()
        .map_err(|e| format!("invalid size: {e:?}"))?;
    let is_binary = view
        .is_binary()
        .map_err(|e| format!("invalid is_binary: {e:?}"))?;
    let truncated = view
        .truncated()
        .map_err(|e| format!("invalid truncated: {e:?}"))?;
    let content = view
        .content()
        .map_err(|e| format!("invalid content: {e:?}"))?
        .to_vec();

    Ok(BlobViewModel {
        revision,
        path,
        oid,
        size,
        is_binary,
        truncated,
        content,
    })
}

/// Decodes raw Protobuf bytes from `ListCommits` into a [`CommitListModel`].
pub fn decode_list_commits_response(bytes: &[u8]) -> Result<CommitListModel, String> {
    let view = ListCommitsResponseView::from_bytes(bytes)
        .map_err(|e| format!("failed to decode ListCommitsResponse: {e:?}"))?;
    let revision = view
        .revision()
        .map_err(|e| format!("invalid revision: {e:?}"))?
        .trim()
        .to_owned();
    let has_more = view
        .has_more()
        .map_err(|e| format!("invalid has_more: {e:?}"))?;

    let mut commits = Vec::new();
    for item in view.commits() {
        let commit_view = item.map_err(|e| format!("invalid CommitInfo: {e:?}"))?;
        commits.push(decode_commit_info_view(commit_view)?);
    }

    Ok(CommitListModel {
        revision,
        commits,
        has_more,
    })
}

/// Decodes raw Protobuf bytes from `GetCommit` into a [`CommitDetailModel`].
pub fn decode_get_commit_response(bytes: &[u8]) -> Result<CommitDetailModel, String> {
    let view = GetCommitResponseView::from_bytes(bytes)
        .map_err(|e| format!("failed to decode GetCommitResponse: {e:?}"))?;
    let commit_view = view
        .commit()
        .map_err(|e| format!("invalid commit field: {e:?}"))?
        .ok_or_else(|| "missing commit field in GetCommitResponse".to_owned())?;
    let commit = decode_commit_info_view(commit_view)?;

    let mut files = Vec::new();
    for item in view.files() {
        let file_view = item.map_err(|e| format!("invalid CommitFileDiff: {e:?}"))?;
        files.push(decode_commit_file_diff_view(file_view)?);
    }

    let total_additions = view
        .total_additions()
        .map_err(|e| format!("invalid total_additions: {e:?}"))?;
    let total_deletions = view
        .total_deletions()
        .map_err(|e| format!("invalid total_deletions: {e:?}"))?;
    let patch = view
        .patch()
        .map_err(|e| format!("invalid patch: {e:?}"))?
        .to_owned();

    Ok(CommitDetailModel {
        commit,
        files,
        total_additions,
        total_deletions,
        patch,
    })
}

fn make_nav_click(on_navigate: &Callback<AppRoute>, target: AppRoute) -> Callback<MouseEvent> {
    let cb = on_navigate.clone();
    Callback::from(move |e: MouseEvent| {
        if !e.ctrl_key() && !e.meta_key() && !e.shift_key() && !e.alt_key() && e.button() == 0 {
            e.prevent_default();
            cb.emit(target.clone());
        }
    })
}

/// Renders the repository header (`scope / owner / visibility / name`, visibility badge,
/// `git clone` snippet, Branch & Tag selector `<select>`, and `Tree` / `Commits` tabs).
#[allow(clippy::too_many_arguments)]
pub fn render_repository_header(
    repo: &RepoCoordinates,
    overview: Option<&RepositoryOverviewModel>,
    active_revision: &str,
    is_commits_tab: bool,
    ssh_host: &str,
    auth_user: Option<&str>,
    copied_target: Option<&CopyTarget>,
    trigger_copy: &Callback<(String, CopyTarget)>,
    on_navigate: &Callback<AppRoute>,
    on_revision_change: Callback<Event>,
) -> Html {
    let item = overview
        .map(|o| o.repository.clone())
        .unwrap_or_else(|| {
            RepositoryItem::new(
                ssh_host,
                auth_user,
                &repo.scope,
                &repo.owner,
                &repo.visibility,
                &repo.name,
            )
        });

    let canonical = item.canonical_path.clone();
    let clone_cmd = item.clone_command_for(ssh_host, auth_user);
    let ssh_url = item.ssh_url_for(ssh_host, auth_user);
    let scope_badge = repo.scope_badge();
    let vis_badge = repo.visibility_badge();

    let clone_target = CopyTarget::CloneCommand(canonical.clone());
    let ssh_target = CopyTarget::SshUrl(canonical);
    let is_clone_copied = copied_target == Some(&clone_target);
    let is_ssh_copied = copied_target == Some(&ssh_target);
    let clone_btn_label = copy_button_label(copied_target, &clone_target, "Copy git clone");
    let ssh_btn_label = copy_button_label(copied_target, &ssh_target, "Copy SSH URL");

    let on_copy_clone = {
        let trigger_copy = trigger_copy.clone();
        let clone_cmd = clone_cmd.clone();
        let clone_target = clone_target.clone();
        Callback::from(move |_: MouseEvent| {
            trigger_copy.emit((clone_cmd.clone(), clone_target.clone()));
        })
    };

    let on_copy_ssh = {
        let trigger_copy = trigger_copy.clone();
        let ssh_url = ssh_url.clone();
        let ssh_target = ssh_target.clone();
        Callback::from(move |_: MouseEvent| {
            trigger_copy.emit((ssh_url.clone(), ssh_target.clone()));
        })
    };

    let effective_rev = if !active_revision.trim().is_empty() {
        active_revision.trim()
    } else if let Some(ov) = overview {
        ov.effective_revision()
    } else {
        DEFAULT_REVISION
    };

    let branches = overview.map(|o| o.branches.as_slice()).unwrap_or(&[]);
    let tags = overview.map(|o| o.tags.as_slice()).unwrap_or(&[]);
    let has_matching_ref = branches.iter().any(|b| b.name == effective_rev)
        || tags.iter().any(|t| t.name == effective_rev);

    let tree_route = AppRoute::Tree {
        repo: repo.clone(),
        revision: effective_rev.to_owned(),
        path: String::new(),
    };
    let commits_route = AppRoute::Commits {
        repo: repo.clone(),
        revision: effective_rev.to_owned(),
        path: String::new(),
        offset: 0,
    };

    html! {
        <section class="repo-browser-header" aria-label="Repository Header">
            <div class="repo-header-top">
                <div class="repo-header-title-block">
                    <div class="repo-breadcrumb-bar">
                        <a
                            href="/"
                            class="repo-index-back-link"
                            onclick={make_nav_click(on_navigate, AppRoute::Index)}
                        >
                            { "All Repositories" }
                        </a>
                        <span class="breadcrumb-sep">{ "/" }</span>
                        <span class="repo-coord-seg">{ &repo.scope }</span>
                        <span class="breadcrumb-sep">{ "/" }</span>
                        <span class="repo-coord-seg">{ &repo.owner }</span>
                        <span class="breadcrumb-sep">{ "/" }</span>
                        <span class="repo-coord-seg">{ &repo.visibility }</span>
                        <span class="breadcrumb-sep">{ "/" }</span>
                        <a
                            href={repo.root_route()}
                            class="repo-coord-name"
                            onclick={make_nav_click(on_navigate, AppRoute::RepoRoot { repo: repo.clone() })}
                        >
                            { format!("{}.git", repo.name) }
                        </a>
                        <span class={classes!("badge", format!("badge-scope-{scope_badge}"))}>
                            { scope_badge }
                        </span>
                        <span class={classes!("badge", format!("badge-vis-{vis_badge}"))}>
                            { vis_badge }
                        </span>
                    </div>

                    <div class="repo-clone-bar">
                        <code class="repo-clone-snippet">{ &clone_cmd }</code>
                        <button
                            type="button"
                            class={classes!("btn", "btn-copy", "btn-sm", is_clone_copied.then_some("btn-copied"))}
                            onclick={on_copy_clone}
                            title={clone_cmd}
                        >
                            { clone_btn_label }
                        </button>
                        <button
                            type="button"
                            class={classes!("btn", "btn-copy", "btn-sm", is_ssh_copied.then_some("btn-copied"))}
                            onclick={on_copy_ssh}
                            title={ssh_url}
                        >
                            { ssh_btn_label }
                        </button>
                    </div>
                </div>
            </div>

            <div class="repo-nav-bar">
                <div class="ref-switcher">
                    <label for="repo-ref-select" class="ref-switcher-label">{ "Ref:" }</label>
                    <select
                        id="repo-ref-select"
                        class="ref-select"
                        value={effective_rev.to_owned()}
                        onchange={on_revision_change}
                        aria-label="Branch or Tag Selector"
                    >
                        if !has_matching_ref {
                            <option value={effective_rev.to_owned()} selected=true>
                                { effective_rev }
                            </option>
                        }
                        if !branches.is_empty() {
                            <optgroup label="Branches (refs/heads/*)">
                                { for branches.iter().map(|b| {
                                    let selected = b.name == effective_rev;
                                    html! {
                                        <option value={b.name.clone()} selected={selected}>
                                            { format!("{} ({})", b.name, b.short_oid()) }
                                        </option>
                                    }
                                }) }
                            </optgroup>
                        }
                        if !tags.is_empty() {
                            <optgroup label="Tags (refs/tags/*)">
                                { for tags.iter().map(|t| {
                                    let selected = t.name == effective_rev;
                                    html! {
                                        <option value={t.name.clone()} selected={selected}>
                                            { format!("{} ({})", t.name, t.short_oid()) }
                                        </option>
                                    }
                                }) }
                            </optgroup>
                        }
                    </select>
                </div>

                <nav class="repo-tabs" aria-label="Repository Views">
                    <a
                        href={tree_route.to_path()}
                        class={classes!("repo-tab", (!is_commits_tab).then_some("repo-tab-active"))}
                        onclick={make_nav_click(on_navigate, tree_route)}
                    >
                        { "Tree" }
                    </a>
                    <a
                        href={commits_route.to_path()}
                        class={classes!("repo-tab", is_commits_tab.then_some("repo-tab-active"))}
                        onclick={make_nav_click(on_navigate, commits_route)}
                    >
                        { "Commits" }
                    </a>
                </nav>
            </div>
        </section>
    }
}

/// Renders clickable path breadcrumbs (`repo / dir1 / dir2 / ...`).
pub fn render_path_breadcrumbs(
    repo: &RepoCoordinates,
    revision: &str,
    path: &str,
    leaf_is_blob: bool,
    on_navigate: &Callback<AppRoute>,
) -> Html {
    let crumbs = build_path_breadcrumbs(repo, revision, path, leaf_is_blob);

    html! {
        <nav class="path-breadcrumbs" aria-label="Path Breadcrumbs">
            { for crumbs.iter().enumerate().map(|(idx, item)| {
                let target_route = if item.is_last && leaf_is_blob {
                    AppRoute::Blob {
                        repo: repo.clone(),
                        revision: revision.to_owned(),
                        path: item.path.clone(),
                    }
                } else {
                    AppRoute::Tree {
                        repo: repo.clone(),
                        revision: revision.to_owned(),
                        path: item.path.clone(),
                    }
                };
                html! {
                    <>
                        if idx > 0 {
                            <span class="breadcrumb-sep">{ "/" }</span>
                        }
                        if item.is_last {
                            <span class="breadcrumb-current">{ &item.label }</span>
                        } else {
                            <a
                                href={item.route.clone()}
                                class="breadcrumb-link"
                                onclick={make_nav_click(on_navigate, target_route)}
                            >
                                { &item.label }
                            </a>
                        }
                    </>
                }
            }) }
        </nav>
    }
}

/// Renders the directory tree view (breadcrumbs, directory table with optional `..` row,
/// empty/unborn repository state, and automatic client-side `README.md` panel).
#[allow(clippy::too_many_arguments)]
pub fn render_tree_view(
    repo: &RepoCoordinates,
    revision: &str,
    current_path: &str,
    entries: &[TreeEntryModel],
    is_empty_unborn: bool,
    clone_command: &str,
    readme_blob: Option<&BlobViewModel>,
    on_navigate: &Callback<AppRoute>,
    on_markdown_navigate: Callback<String>,
) -> Html {
    let clean_path = normalize_repo_path("", current_path);

    if is_empty_unborn && clean_path.is_empty() {
        return html! {
            <section class="empty-repo-panel" aria-label="Empty Repository">
                <h3>{ "This repository is empty" }</h3>
                <p class="empty-hint">
                    { "Clone this bare repository over SSH and push your initial commit:" }
                </p>
                <pre class="command-box"><code>{ clone_command }</code></pre>
            </section>
        };
    }

    let parent_route = if !clean_path.is_empty() {
        let parent = parent_dir_path(&clean_path);
        Some(AppRoute::Tree {
            repo: repo.clone(),
            revision: revision.to_owned(),
            path: parent,
        })
    } else {
        None
    };

    let readme_panel = find_readme_entry(entries).and_then(|readme_entry| {
        let blob = readme_blob?;
        if blob.is_binary {
            return None;
        }
        let md_ctx = MarkdownContext::new(
            &repo.scope,
            &repo.owner,
            &repo.visibility,
            &repo.name,
            revision,
            &clean_path,
        )
        .with_on_navigate(on_markdown_navigate);
        let md_html = MarkdownView::render(&MarkdownProps {
            markdown: AttrValue::from(blob.text_lossy()),
            context: Some(md_ctx),
        });
        Some(html! {
            <section class="readme-panel" aria-label="Directory README">
                <div class="readme-panel-header">
                    <span class="readme-title">{ &readme_entry.name }</span>
                </div>
                <div class="readme-panel-body">
                    { md_html }
                </div>
            </section>
        })
    });

    html! {
        <div class="tree-view-container">
            { render_path_breadcrumbs(repo, revision, &clean_path, false, on_navigate) }

            <div class="tree-table-wrapper">
                <table class="tree-table" aria-label="Directory Tree">
                    <thead>
                        <tr>
                            <th class="tree-col-kind">{ "Kind" }</th>
                            <th class="tree-col-name">{ "Name" }</th>
                            <th class="tree-col-mode">{ "Mode" }</th>
                            <th class="tree-col-oid">{ "OID" }</th>
                            <th class="tree-col-size">{ "Size" }</th>
                        </tr>
                    </thead>
                    <tbody>
                        if let Some(parent_target) = parent_route {
                            <tr class="tree-row tree-row-parent" key="..">
                                <td class="tree-col-kind">
                                    <span class="tree-kind-badge tree-kind-dir">{ "dir" }</span>
                                </td>
                                <td class="tree-col-name">
                                    <a
                                        href={parent_target.to_path()}
                                        class="tree-entry-link tree-parent-link"
                                        onclick={make_nav_click(on_navigate, parent_target)}
                                    >
                                        { ".." }
                                    </a>
                                </td>
                                <td class="tree-col-mode"><code>{ "040000" }</code></td>
                                <td class="tree-col-oid"><code>{ "—" }</code></td>
                                <td class="tree-col-size">{ "—" }</td>
                            </tr>
                        }

                        if entries.is_empty() {
                            <tr>
                                <td colspan="5" class="tree-empty-cell">
                                    { "No entries found in this directory." }
                                </td>
                            </tr>
                        } else {
                            { for entries.iter().map(|entry| {
                                render_tree_entry_row(repo, revision, entry, on_navigate)
                            }) }
                        }
                    </tbody>
                </table>
            </div>

            { for readme_panel }
        </div>
    }
}

fn render_tree_entry_row(
    repo: &RepoCoordinates,
    revision: &str,
    entry: &TreeEntryModel,
    on_navigate: &Callback<AppRoute>,
) -> Html {
    let kind_class = format!("tree-kind-{}", entry.kind);
    let name_cell = if entry.is_dir() {
        let target = AppRoute::Tree {
            repo: repo.clone(),
            revision: revision.to_owned(),
            path: entry.path.clone(),
        };
        html! {
            <a
                href={target.to_path()}
                class="tree-entry-link tree-entry-dir"
                onclick={make_nav_click(on_navigate, target)}
            >
                { format!("{}/", entry.name) }
            </a>
        }
    } else if entry.is_submodule() {
        html! {
            <span class="tree-entry-submodule">
                { format!("{} @ {}", entry.name, entry.short_oid()) }
            </span>
        }
    } else {
        let target = AppRoute::Blob {
            repo: repo.clone(),
            revision: revision.to_owned(),
            path: entry.path.clone(),
        };
        html! {
            <a
                href={target.to_path()}
                class="tree-entry-link tree-entry-file"
                onclick={make_nav_click(on_navigate, target)}
            >
                { &entry.name }
            </a>
        }
    };

    html! {
        <tr class="tree-row" key={entry.path.clone()}>
            <td class="tree-col-kind">
                <span class={classes!("tree-kind-badge", kind_class)}>
                    { &entry.kind }
                </span>
            </td>
            <td class="tree-col-name">{ name_cell }</td>
            <td class="tree-col-mode"><code>{ &entry.mode }</code></td>
            <td class="tree-col-oid"><code>{ entry.short_oid() }</code></td>
            <td class="tree-col-size">{ entry.formatted_size() }</td>
        </tr>
    }
}

/// Renders the blob viewer (breadcrumbs, metadata bar, `Rendered` vs. `Raw` toggle for Markdown,
/// binary file indicator, truncation warning, and line-numbered source code view).
pub fn render_blob_view(
    repo: &RepoCoordinates,
    blob: &BlobViewModel,
    entry_mode: Option<&str>,
    view_mode: BlobViewMode,
    on_mode_change: Callback<BlobViewMode>,
    on_navigate: &Callback<AppRoute>,
    on_markdown_navigate: Callback<String>,
) -> Html {
    let is_md = blob.is_markdown();
    let mode_label = entry_mode.filter(|m| !m.is_empty()).unwrap_or("100644");

    let body_html = if blob.is_binary {
        html! {
            <div class="blob-binary-notice" role="status">
                <code>{ format!("Binary file ({})", blob.formatted_size()) }</code>
            </div>
        }
    } else if is_md && view_mode == BlobViewMode::Rendered {
        let md_ctx = MarkdownContext::new(
            &repo.scope,
            &repo.owner,
            &repo.visibility,
            &repo.name,
            &blob.revision,
            &blob.parent_dir(),
        )
        .with_on_navigate(on_markdown_navigate);
        let md_html = MarkdownView::render(&MarkdownProps {
            markdown: AttrValue::from(blob.text_lossy()),
            context: Some(md_ctx),
        });
        html! {
            <div class="blob-markdown-view">
                { md_html }
            </div>
        }
    } else {
        let text = blob.text_lossy();
        let lines = split_source_lines(&text);
        html! {
            <div class="blob-code-wrapper">
                <table class="blob-code-table" aria-label="Source Code">
                    <tbody>
                        if lines.is_empty() {
                            <tr class="code-line-row">
                                <td class="code-line-num">{ "1" }</td>
                                <td class="code-line-text"><code>{ "" }</code></td>
                            </tr>
                        } else {
                            { for lines.iter().enumerate().map(|(idx, line)| {
                                let line_no = idx + 1;
                                html! {
                                    <tr class="code-line-row" key={line_no}>
                                        <td class="code-line-num" id={format!("L{line_no}")}>
                                            { line_no }
                                        </td>
                                        <td class="code-line-text">
                                            <code>{ *line }</code>
                                        </td>
                                    </tr>
                                }
                            }) }
                        }
                    </tbody>
                </table>
            </div>
        }
    };

    html! {
        <div class="blob-view-container">
            { render_path_breadcrumbs(repo, &blob.revision, &blob.path, true, on_navigate) }

            <section class="blob-panel" aria-label="Blob Viewer">
                <div class="blob-panel-header">
                    <div class="blob-meta-info">
                        <span class="blob-meta-item">
                            { "Mode: " }<code>{ mode_label }</code>
                        </span>
                        <span class="blob-meta-sep">{ "·" }</span>
                        <span class="blob-meta-item">
                            { "Size: " }<code>{ blob.formatted_size() }</code>
                        </span>
                        <span class="blob-meta-sep">{ "·" }</span>
                        <span class="blob-meta-item">
                            { "OID: " }<code>{ blob.short_oid() }</code>
                        </span>
                    </div>

                    if is_md {
                        <div class="blob-mode-toggle" role="group" aria-label="Markdown Display Mode">
                            <button
                                type="button"
                                class={classes!(
                                    "btn",
                                    "btn-sm",
                                    "toggle-btn",
                                    (view_mode == BlobViewMode::Rendered).then_some("toggle-btn-active")
                                )}
                                onclick={{
                                    let on_mode_change = on_mode_change.clone();
                                    Callback::from(move |_: MouseEvent| {
                                        on_mode_change.emit(BlobViewMode::Rendered);
                                    })
                                }}
                            >
                                { "Rendered" }
                            </button>
                            <button
                                type="button"
                                class={classes!(
                                    "btn",
                                    "btn-sm",
                                    "toggle-btn",
                                    (view_mode == BlobViewMode::Raw).then_some("toggle-btn-active")
                                )}
                                onclick={{
                                    let on_mode_change = on_mode_change.clone();
                                    Callback::from(move |_: MouseEvent| {
                                        on_mode_change.emit(BlobViewMode::Raw);
                                    })
                                }}
                            >
                                { "Raw" }
                            </button>
                        </div>
                    }
                </div>

                if blob.truncated {
                    <div class="blob-truncated-banner" role="alert">
                        { "This blob exceeded the maximum preview size and was truncated." }
                    </div>
                }

                <div class="blob-panel-body">
                    { body_html }
                </div>
            </section>
        </div>
    }
}

/// Renders the paginated commit log (`ListCommits`) with `Previous` and `Next` controls.
pub fn render_commits_view(
    repo: &RepoCoordinates,
    active_revision: &str,
    path_filter: &str,
    offset: u32,
    limit: u32,
    commit_list: &CommitListModel,
    on_navigate: &Callback<AppRoute>,
) -> Html {
    let page_size = if limit == 0 { COMMITS_PAGE_SIZE } else { limit };
    let rev = if !commit_list.revision.is_empty() {
        commit_list.revision.as_str()
    } else if !active_revision.is_empty() {
        active_revision
    } else {
        DEFAULT_REVISION
    };

    let has_prev = offset > 0;
    let has_next = commit_list.has_more;
    let prev_offset = offset.saturating_sub(page_size);
    let next_offset = offset.saturating_add(page_size);

    let prev_route = AppRoute::Commits {
        repo: repo.clone(),
        revision: rev.to_owned(),
        path: path_filter.to_owned(),
        offset: prev_offset,
    };
    let next_route = AppRoute::Commits {
        repo: repo.clone(),
        revision: rev.to_owned(),
        path: path_filter.to_owned(),
        offset: next_offset,
    };

    html! {
        <section class="commits-view-container" aria-label="Commit Log">
            <div class="commits-header-bar">
                <div class="commits-title-group">
                    <h2 class="commits-heading">{ format!("Commits on {rev}") }</h2>
                    if !path_filter.is_empty() {
                        <span class="commits-path-filter">
                            { "Path: " }<code>{ path_filter }</code>
                        </span>
                    }
                </div>
                <span class="commits-range-label">
                    { if commit_list.commits.is_empty() {
                        "0 commits".to_owned()
                    } else {
                        format!(
                            "Showing {}–{}",
                            offset + 1,
                            offset + (commit_list.commits.len() as u32)
                        )
                    } }
                </span>
            </div>

            if commit_list.commits.is_empty() {
                <div class="empty-state">
                    <p>{ "No commits found for this revision." }</p>
                </div>
            } else {
                <div class="commit-log-list">
                    { for commit_list.commits.iter().map(|commit| {
                        let detail_route = AppRoute::CommitDetail {
                            repo: repo.clone(),
                            revision: commit.oid.clone(),
                        };
                        let detail_href = detail_route.to_path();
                        html! {
                            <article class="commit-log-row" key={commit.oid.clone()}>
                                <div class="commit-log-main">
                                    <a
                                        href={detail_href.clone()}
                                        class="commit-subject-link"
                                        onclick={make_nav_click(on_navigate, detail_route.clone())}
                                    >
                                        { &commit.subject }
                                    </a>
                                    <div class="commit-meta-line">
                                        <span class="commit-author">
                                            { format!("{} <{}>", commit.author_name, commit.author_email) }
                                        </span>
                                        <span class="blob-meta-sep">{ "·" }</span>
                                        <time class="commit-time">
                                            { format_unix_timestamp(commit.author_time_secs) }
                                        </time>
                                    </div>
                                </div>
                                <div class="commit-log-actions">
                                    <a
                                        href={detail_href}
                                        class="commit-oid-badge"
                                        onclick={make_nav_click(on_navigate, detail_route)}
                                        title={commit.oid.clone()}
                                    >
                                        <code>{ commit.short_oid() }</code>
                                    </a>
                                </div>
                            </article>
                        }
                    }) }
                </div>
            }

            <div class="pagination-bar" aria-label="Commit Log Pagination">
                <button
                    type="button"
                    class="btn btn-secondary"
                    disabled={!has_prev}
                    onclick={{
                        let on_navigate = on_navigate.clone();
                        Callback::from(move |_: MouseEvent| {
                            if has_prev {
                                on_navigate.emit(prev_route.clone());
                            }
                        })
                    }}
                >
                    { "Previous" }
                </button>
                <button
                    type="button"
                    class="btn btn-secondary"
                    disabled={!has_next}
                    onclick={{
                        let on_navigate = on_navigate.clone();
                        Callback::from(move |_: MouseEvent| {
                            if has_next {
                                on_navigate.emit(next_route.clone());
                            }
                        })
                    }}
                >
                    { "Next" }
                </button>
            </div>
        </section>
    }
}

/// Renders the individual commit detail header, diff summary, and per-file unified diff cards (`GetCommit`).
pub fn render_commit_detail_view(
    repo: &RepoCoordinates,
    detail: &CommitDetailModel,
    on_navigate: &Callback<AppRoute>,
) -> Html {
    let commit = &detail.commit;
    let body_text = commit.body();
    let files_count = detail.files.len();
    let files_label = if files_count == 1 {
        "1 file changed".to_owned()
    } else {
        format!("{files_count} files changed")
    };

    let tree_at_commit = AppRoute::Tree {
        repo: repo.clone(),
        revision: commit.oid.clone(),
        path: String::new(),
    };

    html! {
        <div class="commit-detail-container">
            <section class="commit-detail-card" aria-label="Commit Metadata">
                <div class="commit-detail-header">
                    <div class="commit-detail-title-row">
                        <h2 class="commit-detail-subject">{ &commit.subject }</h2>
                        <a
                            href={tree_at_commit.to_path()}
                            class="btn btn-secondary btn-sm"
                            onclick={make_nav_click(on_navigate, tree_at_commit)}
                        >
                            { "Browse Tree at Commit" }
                        </a>
                    </div>
                    if !body_text.is_empty() {
                        <pre class="commit-detail-body">{ body_text }</pre>
                    }
                </div>

                <div class="commit-detail-meta-grid">
                    <div class="commit-meta-row">
                        <span class="commit-meta-label">{ "Commit:" }</span>
                        <code class="commit-full-oid">{ &commit.oid }</code>
                    </div>
                    <div class="commit-meta-row">
                        <span class="commit-meta-label">{ "Parents:" }</span>
                        <span class="commit-parents-list">
                            if commit.parent_oids.is_empty() {
                                <span class="commit-root-badge">{ "None (root commit)" }</span>
                            } else {
                                { for commit.parent_oids.iter().map(|parent_oid| {
                                    let parent_route = AppRoute::CommitDetail {
                                        repo: repo.clone(),
                                        revision: parent_oid.clone(),
                                    };
                                    html! {
                                        <a
                                            href={parent_route.to_path()}
                                            class="commit-oid-badge commit-parent-link"
                                            onclick={make_nav_click(on_navigate, parent_route)}
                                            title={parent_oid.clone()}
                                        >
                                            <code>{ short_oid_str(parent_oid) }</code>
                                        </a>
                                    }
                                }) }
                            }
                        </span>
                    </div>
                    <div class="commit-meta-row">
                        <span class="commit-meta-label">{ "Author:" }</span>
                        <span>
                            { format!("{} <{}> · {}", commit.author_name, commit.author_email, format_unix_timestamp(commit.author_time_secs)) }
                        </span>
                    </div>
                    <div class="commit-meta-row">
                        <span class="commit-meta-label">{ "Committer:" }</span>
                        <span>
                            { format!("{} <{}> · {}", commit.committer_name, commit.committer_email, format_unix_timestamp(commit.committer_time_secs)) }
                        </span>
                    </div>
                </div>
            </section>

            <div class="diff-summary-bar" aria-label="Diff Summary">
                <span class="diff-files-count">{ files_label }</span>
                <div class="diff-stat-pills">
                    <span class="diff-stat-add">{ format!("+{}", detail.total_additions) }</span>
                    <span class="diff-stat-del">{ format!("-{}", detail.total_deletions) }</span>
                </div>
            </div>

            <div class="diff-files-list">
                { for detail.files.iter().map(|file| {
                    render_commit_file_diff_card(repo, &commit.oid, file, on_navigate)
                }) }
            </div>
        </div>
    }
}

fn render_commit_file_diff_card(
    repo: &RepoCoordinates,
    commit_oid: &str,
    file: &CommitFileDiffModel,
    on_navigate: &Callback<AppRoute>,
) -> Html {
    let status_class = match file.status.as_str() {
        DIFF_STATUS_ADDED => "diff-status-added",
        DIFF_STATUS_DELETED => "diff-status-deleted",
        DIFF_STATUS_RENAMED => "diff-status-renamed",
        DIFF_STATUS_COPIED => "diff-status-copied",
        DIFF_STATUS_TYPECHANGE => "diff-status-typechange",
        _ => "diff-status-modified",
    };

    let display_path = file.display_path();
    let patch_lines = split_source_lines(&file.patch);

    let path_node = if file.status != DIFF_STATUS_DELETED && !file.path.is_empty() {
        let blob_target = AppRoute::Blob {
            repo: repo.clone(),
            revision: commit_oid.to_owned(),
            path: file.path.clone(),
        };
        html! {
            <a
                href={blob_target.to_path()}
                class="diff-file-path-link"
                onclick={make_nav_click(on_navigate, blob_target)}
            >
                <code>{ display_path }</code>
            </a>
        }
    } else {
        html! {
            <code class="diff-file-path">{ display_path }</code>
        }
    };

    html! {
        <section class="diff-file-card" key={format!("{}:{}", file.status, file.path)}>
            <div class="diff-file-header">
                <div class="diff-file-title">
                    <span class={classes!("badge", "diff-status-badge", status_class)}>
                        { &file.status }
                    </span>
                    { path_node }
                </div>
                <div class="diff-stat-pills">
                    <span class="diff-stat-add">{ format!("+{}", file.additions) }</span>
                    <span class="diff-stat-del">{ format!("-{}", file.deletions) }</span>
                </div>
            </div>

            if patch_lines.is_empty() {
                <div class="diff-empty-patch">
                    { "No textual diff lines for this entry." }
                </div>
            } else {
                <div class="diff-patch-wrapper">
                    <table class="diff-patch-table" aria-label={format!("Diff for {}", file.path)}>
                        <tbody>
                            { for patch_lines.iter().enumerate().map(|(idx, line)| {
                                let kind = classify_diff_line(line);
                                html! {
                                    <tr class={classes!("diff-line-row", kind.css_class())} key={idx}>
                                        <td class="diff-line-num">{ idx + 1 }</td>
                                        <td class="diff-line-code"><code>{ *line }</code></td>
                                    </tr>
                                }
                            }) }
                        </tbody>
                    </table>
                </div>
            }
        </section>
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::render_vnode_to_html_string;
    use ro_git_proto::ro_git::v1::{
        GetBlobResponseBuilder, GetCommitResponseBuilder, GetRepositoryResponseBuilder,
        GetTreeResponseBuilder, ListCommitsResponseBuilder,
    };

    const OID_A: &str = "0123456789abcdef0123456789abcdef01234567";
    const OID_B: &str = "89abcdef0123456789abcdef0123456789abcdef";
    const OID_C: &str = "fedcba9876543210fedcba9876543210fedcba98";

    #[test]
    fn parses_and_formats_all_client_routes_and_api_urls() {
        assert_eq!(parse_app_route("/"), Some(AppRoute::Index));
        assert_eq!(parse_app_route(""), Some(AppRoute::Index));
        assert_eq!(format_app_route(&AppRoute::Index), "/");

        let repo = RepoCoordinates::new("users", "alice", "public", "demo.git").unwrap();
        assert_eq!(repo.name, "demo");
        assert_eq!(repo.canonical_path(), "/users/alice/public/demo.git");
        assert_eq!(repo.display_title(), "users / alice / public / demo");
        assert_eq!(repo.scope_badge(), "user");
        assert_eq!(repo.visibility_badge(), "public");

        // RepoRoot
        let root_route = AppRoute::RepoRoot { repo: repo.clone() };
        assert_eq!(root_route.to_path(), "/users/alice/public/demo");
        assert_eq!(
            parse_app_route("/users/alice/public/demo"),
            Some(root_route.clone())
        );
        assert_eq!(
            parse_app_route("/users/alice/public/demo.git/"),
            Some(root_route)
        );

        // Tree root & nested paths
        let tree_root = AppRoute::Tree {
            repo: repo.clone(),
            revision: "main".to_owned(),
            path: String::new(),
        };
        assert_eq!(tree_root.to_path(), "/users/alice/public/demo/tree/main");
        assert_eq!(
            parse_app_route("/users/alice/public/demo/tree/main"),
            Some(tree_root)
        );

        let tree_nested = AppRoute::Tree {
            repo: repo.clone(),
            revision: "feature/auth".to_owned(),
            path: "crates/ro-git-ui/src".to_owned(),
        };
        assert_eq!(
            tree_nested.to_path(),
            "/users/alice/public/demo/tree/feature%2Fauth/crates/ro-git-ui/src"
        );
        assert_eq!(
            parse_app_route(&tree_nested.to_path()),
            Some(tree_nested.clone())
        );

        // Blob route
        let blob_route = AppRoute::Blob {
            repo: repo.clone(),
            revision: "v1.0.0".to_owned(),
            path: "docs/guide.md".to_owned(),
        };
        assert_eq!(
            blob_route.to_path(),
            "/users/alice/public/demo/blob/v1.0.0/docs/guide.md"
        );
        assert_eq!(
            parse_app_route("/users/alice/public/demo/blob/v1.0.0/docs/guide.md#install"),
            Some(blob_route.clone())
        );

        // Commits routes (default, with revision, with path and offset)
        assert_eq!(
            parse_app_route("/users/alice/public/demo/commits"),
            Some(AppRoute::Commits {
                repo: repo.clone(),
                revision: "HEAD".to_owned(),
                path: String::new(),
                offset: 0,
            })
        );
        let commits_paged = AppRoute::Commits {
            repo: repo.clone(),
            revision: "main".to_owned(),
            path: "src/lib.rs".to_owned(),
            offset: 50,
        };
        assert_eq!(
            commits_paged.to_path(),
            "/users/alice/public/demo/commits/main/src/lib.rs?offset=50"
        );
        assert_eq!(
            parse_app_route(&commits_paged.to_path()),
            Some(commits_paged.clone())
        );
        assert_eq!(
            parse_app_route("/users/alice/public/demo/commits?revision=v1.0.0&path=README.md&offset=100"),
            Some(AppRoute::Commits {
                repo: repo.clone(),
                revision: "v1.0.0".to_owned(),
                path: "README.md".to_owned(),
                offset: 100,
            })
        );

        // CommitDetail route
        let commit_detail = AppRoute::CommitDetail {
            repo: repo.clone(),
            revision: OID_A.to_owned(),
        };
        assert_eq!(
            commit_detail.to_path(),
            format!("/users/alice/public/demo/commit/{OID_A}")
        );
        assert_eq!(
            parse_app_route(&commit_detail.to_path()),
            Some(commit_detail.clone())
        );
        assert!(commit_detail.is_commits_tab());
        assert!(!blob_route.is_commits_tab());

        // Switching revision preserves current view and path
        assert_eq!(
            blob_route.with_revision("develop"),
            AppRoute::Blob {
                repo: repo.clone(),
                revision: "develop".to_owned(),
                path: "docs/guide.md".to_owned(),
            }
        );
        assert_eq!(
            commits_paged.with_revision("develop"),
            AppRoute::Commits {
                repo: repo.clone(),
                revision: "develop".to_owned(),
                path: "src/lib.rs".to_owned(),
                offset: 0,
            }
        );

        // Invalid routes rejected
        assert_eq!(parse_app_route("/orgs/alice/public/demo"), None);
        assert_eq!(parse_app_route("/users/alice/internal/demo"), None);
        assert_eq!(parse_app_route("/users/alice/public"), None);
        assert_eq!(parse_app_route("/users/alice/public/demo/blob/main"), None);
        assert_eq!(
            parse_app_route("/users/alice/public/demo/blob/main/../etc/passwd"),
            None
        );
        assert_eq!(
            parse_app_route("/users/alice/public/demo/tree/-flag"),
            None
        );
        assert_eq!(
            parse_app_route("/users/alice/public/demo/unknown/main"),
            None
        );

        // API URL builders
        assert_eq!(
            build_repository_api_url("users", "alice", "public", "demo.git", Some("feature/a")),
            "/api/v1/repositories/users/alice/public/demo?revision=feature%2Fa"
        );
        assert_eq!(
            build_tree_api_url("users", "alice", "public", "demo", "main", "src/ui"),
            "/api/v1/repositories/users/alice/public/demo/tree?revision=main&path=src%2Fui"
        );
        assert_eq!(
            build_blob_api_url("users", "alice", "public", "demo", "main", "README.md"),
            "/api/v1/repositories/users/alice/public/demo/blob?revision=main&path=README.md"
        );
        assert_eq!(
            build_commits_api_url("teams", "core", "private", "infra", "main", "src", 50, 100),
            "/api/v1/repositories/teams/core/private/infra/commits?revision=main&path=src&limit=50&offset=100"
        );
        assert_eq!(
            build_commit_api_url("teams", "core", "private", "infra", OID_A),
            format!("/api/v1/repositories/teams/core/private/infra/commit?revision={OID_A}")
        );
    }

    #[test]
    fn decodes_repository_tree_blob_commits_and_commit_detail_protobuf_responses() {
        // 1. GetRepositoryResponse (fields written in reverse tag order!)
        let mut buf = vec![0u8; 4096];
        let mut gr = GetRepositoryResponseBuilder::new(&mut buf);
        gr.write_entries(|e| {
            e.write_size(128)
                .write_oid(OID_B)
                .write_path("README.md")
                .write_name("README.md")
                .write_kind(TREE_KIND_FILE)
                .write_mode("100644");
        });
        gr.check().unwrap();
        gr.write_entries(|e| {
            e.write_size(0)
                .write_oid(OID_A)
                .write_path("src")
                .write_name("src")
                .write_kind(TREE_KIND_DIR)
                .write_mode("040000");
        });
        gr.check().unwrap();
        gr.write_tags(|t| {
            t.write_oid(OID_A)
                .write_full_name("refs/tags/v1.0.0")
                .write_name("v1.0.0");
        });
        gr.check().unwrap();
        gr.write_branches(|b| {
            b.write_oid(OID_A)
                .write_full_name("refs/heads/main")
                .write_name("main");
        });
        gr.check().unwrap();
        gr.write_resolved_revision("main")
            .write_head_oid(OID_A)
            .write_head_ref("main")
            .write_repository(|r| {
                r.write_clone_command("git clone ssh://localhost/users/alice/public/demo.git")
                    .write_ssh_url("ssh://localhost/users/alice/public/demo.git")
                    .write_canonical_path("/users/alice/public/demo.git")
                    .write_name("demo")
                    .write_visibility("public")
                    .write_owner("alice")
                    .write_scope("users");
            });
        let gr_bytes = gr.finish().unwrap();
        let overview = decode_get_repository_response(gr_bytes).unwrap();
        assert_eq!(overview.repository.name, "demo");
        assert_eq!(overview.head_ref, "main");
        assert_eq!(overview.effective_revision(), "main");
        assert!(!overview.is_empty_unborn());
        assert_eq!(overview.branches.len(), 1);
        assert!(overview.branches[0].is_branch());
        assert_eq!(overview.branches[0].short_oid(), "0123456");
        assert_eq!(overview.tags.len(), 1);
        assert!(overview.tags[0].is_tag());
        assert_eq!(overview.entries.len(), 2);
        assert!(overview.entries[0].is_dir());
        assert!(overview.entries[1].is_file());
        assert_eq!(
            find_readme_entry(&overview.entries).map(|e| e.name.as_str()),
            Some("README.md")
        );

        // 2. GetTreeResponse
        let mut tree_buf = vec![0u8; 2048];
        let mut gt = GetTreeResponseBuilder::new(&mut tree_buf);
        gt.write_entries(|e| {
            e.write_size(2048)
                .write_oid(OID_C)
                .write_path("src/lib.rs")
                .write_name("lib.rs")
                .write_kind(TREE_KIND_FILE)
                .write_mode("100644");
        });
        gt.check().unwrap();
        gt.write_path("src")
            .write_tree_oid(OID_B)
            .write_revision("main");
        let gt_bytes = gt.finish().unwrap();
        let tree_model = decode_get_tree_response(gt_bytes).unwrap();
        assert_eq!(tree_model.revision, "main");
        assert_eq!(tree_model.path, "src");
        assert_eq!(tree_model.entries.len(), 1);
        assert_eq!(tree_model.entries[0].formatted_size(), "2.0 KiB");

        // 3. GetBlobResponse
        let mut blob_buf = vec![0u8; 2048];
        let mut gb = GetBlobResponseBuilder::new(&mut blob_buf);
        gb.write_content(b"# Demo\nHello world\n")
            .write_truncated(false)
            .write_is_binary(false)
            .write_size(19)
            .write_oid(OID_B)
            .write_path("docs/README.md")
            .write_revision("main");
        let gb_bytes = gb.finish().unwrap();
        let blob_model = decode_get_blob_response(gb_bytes).unwrap();
        assert!(blob_model.is_markdown());
        assert_eq!(blob_model.parent_dir(), "docs");
        assert_eq!(blob_model.formatted_size(), "19 B");
        assert_eq!(blob_model.text_lossy(), "# Demo\nHello world\n");

        // 4. ListCommitsResponse
        let mut lc_buf = vec![0u8; 4096];
        let mut lc = ListCommitsResponseBuilder::new(&mut lc_buf);
        lc.write_has_more(true);
        lc.write_commits(|c| {
            c.write_message("Initial commit\n\nDetailed body line.")
                .write_subject("Initial commit")
                .write_committer_time_secs(1_700_000_000)
                .write_committer_email("alice@example.com")
                .write_committer_name("Alice")
                .write_author_time_secs(1_700_000_000)
                .write_author_email("alice@example.com")
                .write_author_name("Alice")
                .write_parent_oids(OID_B);
            c.check().unwrap();
            c.write_oid(OID_A);
        });
        lc.check().unwrap();
        lc.write_revision("main");
        let lc_bytes = lc.finish().unwrap();
        let commit_list = decode_list_commits_response(lc_bytes).unwrap();
        assert_eq!(commit_list.revision, "main");
        assert!(commit_list.has_more);
        assert_eq!(commit_list.commits.len(), 1);
        assert_eq!(commit_list.commits[0].short_oid(), "0123456");
        assert_eq!(commit_list.commits[0].body(), "Detailed body line.");

        // 5. GetCommitResponse
        let mut gc_buf = vec![0u8; 4096];
        let mut gc = GetCommitResponseBuilder::new(&mut gc_buf);
        gc.write_patch("@@ -1 +1,2 @@\n-old\n+new\n+line2\n")
            .write_total_deletions(1)
            .write_total_additions(2);
        gc.write_files(|f| {
            f.write_patch("@@ -1 +1,2 @@\n-old\n+new\n+line2\n")
                .write_deletions(1)
                .write_additions(2)
                .write_status(DIFF_STATUS_RENAMED)
                .write_old_path("old.rs")
                .write_path("new.rs");
        });
        gc.check().unwrap();
        gc.write_commit(|c| {
            c.write_message("Rename file\n\nMoved old.rs to new.rs")
                .write_subject("Rename file")
                .write_committer_time_secs(1_700_000_000)
                .write_committer_email("alice@example.com")
                .write_committer_name("Alice")
                .write_author_time_secs(1_700_000_000)
                .write_author_email("alice@example.com")
                .write_author_name("Alice")
                .write_parent_oids(OID_B);
            c.check().unwrap();
            c.write_oid(OID_A);
        });
        let gc_bytes = gc.finish().unwrap();
        let commit_detail = decode_get_commit_response(gc_bytes).unwrap();
        assert_eq!(commit_detail.commit.oid, OID_A);
        assert_eq!(commit_detail.total_additions, 2);
        assert_eq!(commit_detail.total_deletions, 1);
        assert_eq!(commit_detail.files.len(), 1);
        assert_eq!(commit_detail.files[0].display_path(), "old.rs -> new.rs");
    }

    #[test]
    fn tests_readme_detection_breadcrumbs_sizes_lines_and_diff_classification() {
        let entries = vec![
            TreeEntryModel {
                mode: "040000".to_owned(),
                kind: TREE_KIND_DIR.to_owned(),
                name: "README.md".to_owned(),
                path: "README.md".to_owned(),
                oid: OID_A.to_owned(),
                size: 0,
            },
            TreeEntryModel {
                mode: "100644".to_owned(),
                kind: TREE_KIND_FILE.to_owned(),
                name: "readme.markdown".to_owned(),
                path: "readme.markdown".to_owned(),
                oid: OID_B.to_owned(),
                size: 42,
            },
        ];
        assert_eq!(
            find_readme_entry(&entries).map(|e| e.name.as_str()),
            Some("readme.markdown")
        );

        assert!(is_markdown_path("README.md"));
        assert!(is_markdown_path("docs/Guide.MARKDOWN"));
        assert!(!is_markdown_path("src/main.rs"));
        assert!(!is_markdown_path(".md"));

        assert_eq!(parent_dir_path("crates/ro-git-ui/src/lib.rs"), "crates/ro-git-ui/src");
        assert_eq!(parent_dir_path("README.md"), "");
        assert_eq!(parent_dir_path(""), "");

        let repo = RepoCoordinates::new("users", "alice", "public", "demo").unwrap();
        let crumbs = build_path_breadcrumbs(&repo, "main", "crates/ro-git-ui/lib.rs", true);
        assert_eq!(crumbs.len(), 4);
        assert_eq!(crumbs[0].label, "demo");
        assert_eq!(crumbs[0].route, "/users/alice/public/demo/tree/main");
        assert!(!crumbs[0].is_last);
        assert_eq!(crumbs[2].label, "ro-git-ui");
        assert_eq!(
            crumbs[2].route,
            "/users/alice/public/demo/tree/main/crates/ro-git-ui"
        );
        assert_eq!(crumbs[3].label, "lib.rs");
        assert_eq!(
            crumbs[3].route,
            "/users/alice/public/demo/blob/main/crates/ro-git-ui/lib.rs"
        );
        assert!(crumbs[3].is_last);

        assert_eq!(format_byte_size(0), "0 B");
        assert_eq!(format_byte_size(512), "512 B");
        assert_eq!(format_byte_size(1536), "1.5 KiB");
        assert_eq!(format_byte_size(2 * 1024 * 1024), "2.0 MiB");
        assert_eq!(format_unix_timestamp(1_700_000_000), "2023-11-14 22:13 UTC");

        assert_eq!(split_source_lines(""), Vec::<&str>::new());
        assert_eq!(
            split_source_lines("fn a() {}\r\nfn b() {}\n"),
            vec!["fn a() {}", "fn b() {}"]
        );

        assert_eq!(classify_diff_line("diff --git a/x b/x"), DiffLineKind::Header);
        assert_eq!(classify_diff_line("--- a/x"), DiffLineKind::Header);
        assert_eq!(classify_diff_line("+++ b/x"), DiffLineKind::Header);
        assert_eq!(classify_diff_line("@@ -1,3 +1,4 @@"), DiffLineKind::Hunk);
        assert_eq!(classify_diff_line("+added line"), DiffLineKind::Addition);
        assert_eq!(classify_diff_line("-deleted line"), DiffLineKind::Deletion);
        assert_eq!(classify_diff_line(" context line"), DiffLineKind::Context);
    }

    #[test]
    fn renders_tree_blob_commits_and_diff_vnodes_cleanly() {
        let repo = RepoCoordinates::new("users", "alice", "public", "demo").unwrap();
        let noop_nav = Callback::from(|_: AppRoute| {});
        let noop_md_nav = Callback::from(|_: String| {});
        let noop_copy = Callback::from(|_: (String, CopyTarget)| {});
        let noop_rev = Callback::from(|_: Event| {});

        // Header VNode
        let header_vnode = render_repository_header(
            &repo,
            None,
            "main",
            false,
            "git.example.com",
            Some("alice"),
            None,
            &noop_copy,
            &noop_nav,
            noop_rev,
        );
        let header_html = render_vnode_to_html_string(&header_vnode);
        assert!(header_html.contains("demo.git"));
        assert!(header_html.contains("git clone ssh://alice@git.example.com/users/alice/public/demo.git"));

        // Tree view in subdirectory with `..` parent link and README panel
        let entries = vec![
            TreeEntryModel {
                mode: "040000".to_owned(),
                kind: TREE_KIND_DIR.to_owned(),
                name: "components".to_owned(),
                path: "src/components".to_owned(),
                oid: OID_A.to_owned(),
                size: 0,
            },
            TreeEntryModel {
                mode: "100644".to_owned(),
                kind: TREE_KIND_FILE.to_owned(),
                name: "README.md".to_owned(),
                path: "src/README.md".to_owned(),
                oid: OID_B.to_owned(),
                size: 28,
            },
        ];
        let readme_blob = BlobViewModel {
            revision: "main".to_owned(),
            path: "src/README.md".to_owned(),
            oid: OID_B.to_owned(),
            size: 28,
            is_binary: false,
            truncated: false,
            content: b"# Subdir Readme\nSee [lib](./lib.rs).".to_vec(),
        };
        let tree_vnode = render_tree_view(
            &repo,
            "main",
            "src",
            &entries,
            false,
            "git clone ssh://localhost/users/alice/public/demo.git",
            Some(&readme_blob),
            &noop_nav,
            noop_md_nav.clone(),
        );
        let tree_html = render_vnode_to_html_string(&tree_vnode);
        assert!(tree_html.contains(".."));
        assert!(tree_html.contains("components/"));
        assert!(tree_html.contains("<h1>Subdir Readme</h1>"));
        assert!(tree_html.contains("/users/alice/public/demo/blob/main/src/lib.rs"));

        // Blob view: binary, Markdown Rendered, and Raw with line numbers + truncation
        let bin_blob = BlobViewModel {
            revision: "main".to_owned(),
            path: "assets/logo.png".to_owned(),
            oid: OID_C.to_owned(),
            size: 4096,
            is_binary: true,
            truncated: false,
            content: vec![0, 1, 2, 3],
        };
        let bin_html = render_vnode_to_html_string(&render_blob_view(
            &repo,
            &bin_blob,
            Some("100644"),
            BlobViewMode::Rendered,
            Callback::from(|_: BlobViewMode| {}),
            &noop_nav,
            noop_md_nav.clone(),
        ));
        assert!(bin_html.contains("Binary file (4.0 KiB)"));

        let raw_md_blob = BlobViewModel {
            revision: "main".to_owned(),
            path: "README.md".to_owned(),
            oid: OID_B.to_owned(),
            size: 20,
            is_binary: false,
            truncated: true,
            content: b"# Title\nLine two\n".to_vec(),
        };
        let raw_html = render_vnode_to_html_string(&render_blob_view(
            &repo,
            &raw_md_blob,
            Some("100644"),
            BlobViewMode::Raw,
            Callback::from(|_: BlobViewMode| {}),
            &noop_nav,
            noop_md_nav,
        ));
        assert!(raw_html.contains("Rendered"));
        assert!(raw_html.contains("Raw"));
        assert!(raw_html.contains("truncated"));
        assert!(raw_html.contains("id=\"L1\""));
        assert!(raw_html.contains("id=\"L2\""));

        // Commit detail view with diff lines
        let detail = CommitDetailModel {
            commit: CommitInfoModel {
                oid: OID_A.to_owned(),
                parent_oids: vec![OID_B.to_owned()],
                author_name: "Alice".to_owned(),
                author_email: "alice@example.com".to_owned(),
                author_time_secs: 1_700_000_000,
                committer_name: "Alice".to_owned(),
                committer_email: "alice@example.com".to_owned(),
                committer_time_secs: 1_700_000_000,
                subject: "Update README".to_owned(),
                message: "Update README\n\nMore details.".to_owned(),
            },
            files: vec![CommitFileDiffModel {
                path: "README.md".to_owned(),
                old_path: "OLD_README.md".to_owned(),
                status: DIFF_STATUS_RENAMED.to_owned(),
                additions: 2,
                deletions: 1,
                patch: "@@ -1 +1,2 @@\n-old\n+new1\n+new2".to_owned(),
            }],
            total_additions: 2,
            total_deletions: 1,
            patch: String::new(),
        };
        let detail_html =
            render_vnode_to_html_string(&render_commit_detail_view(&repo, &detail, &noop_nav));
        assert!(detail_html.contains("1 file changed"));
        assert!(detail_html.contains("OLD_README.md -&gt; README.md"));
        assert!(detail_html.contains("diff-line-hunk"));
        assert!(detail_html.contains("diff-line-add"));
        assert!(detail_html.contains("diff-line-del"));

        // Commits list view with pagination and path filter
        let commit_list = CommitListModel {
            revision: "main".to_owned(),
            commits: vec![detail.commit.clone()],
            has_more: true,
        };
        let commits_html = render_vnode_to_html_string(&render_commits_view(
            &repo,
            "main",
            "src",
            30,
            COMMITS_PAGE_SIZE,
            &commit_list,
            &noop_nav,
        ));
        assert!(commits_html.contains("Update README"));
        assert!(commits_html.contains("0123456"));
        assert!(commits_html.contains("Previous"));
        assert!(commits_html.contains("Next"));
        assert!(commits_html.contains("Path: <code>src</code>"));

        // Empty / unborn repository tree view
        let unborn_html = render_vnode_to_html_string(&render_tree_view(
            &repo,
            "HEAD",
            "",
            &[],
            true,
            "git clone ssh://localhost/users/alice/public/demo.git",
            None,
            &noop_nav,
            Callback::from(|_: String| {}),
        ));
        assert!(unborn_html.contains("This repository is empty"));
        assert!(unborn_html.contains("git clone ssh://localhost/users/alice/public/demo.git"));

        // Decoder error handling on malformed / empty payloads
        assert!(decode_get_repository_response(&[]).is_err());
        assert!(decode_get_repository_response(&[0xFF, 0xFF]).is_err());
        assert!(decode_get_tree_response(&[0xFF, 0xFF]).is_err());
        assert!(decode_get_blob_response(&[0xFF, 0xFF]).is_err());
        assert!(decode_list_commits_response(&[0xFF, 0xFF]).is_err());
        assert!(decode_get_commit_response(&[]).is_err());
    }
}
