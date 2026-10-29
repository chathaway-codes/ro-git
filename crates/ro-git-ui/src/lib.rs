#![forbid(unsafe_code)]

pub mod app;
pub mod markdown;
pub mod repo_browser;

pub use app::App;
pub use markdown::{
    is_safe_markdown_url, markdown_options, normalize_repo_path, render_markdown,
    render_vnode_to_html_string, resolve_markdown_url, MarkdownContext, MarkdownProps,
    MarkdownView,
};
pub use repo_browser::*;

use ro_git_proto::ro_git::v1::{GetAuthStatusResponseView, ListRepositoriesResponseView};
use ro_git_proto::{
    encode_bearer_token, format_authenticated_ssh_url, format_canonical_path, format_clone_command,
    format_ssh_keygen_sign_command, format_token_payload, is_valid_identifier, normalize_ssh_host,
    strip_git_suffix, validate_token_claims, TokenError, SCOPE_TEAMS, SCOPE_USERS,
    VISIBILITY_PRIVATE, VISIBILITY_PUBLIC,
};

/// Browser `localStorage` key used to persist the stateless SSH bearer token.
pub const LOCAL_STORAGE_TOKEN_KEY: &str = "ro_git_bearer_token";

/// Fallback SSH hostname when the backend omits `ssh_host`.
pub const DEFAULT_SSH_HOST: &str = "localhost";

/// Maximum allowed token TTL in seconds (30 days).
pub const MAX_TOKEN_TTL_SECS: u64 = 2_592_000;

/// Default token TTL selected in the SSH Sign-In modal (24 hours).
pub const DEFAULT_TTL_SECS: u64 = 86_400;

/// Selectable token lifetime preset for the SSH Sign-In modal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TtlOption {
    pub label: &'static str,
    pub seconds: u64,
}

/// Standard TTL options offered in the SSH Sign-In modal (up to 30 days max).
pub const TTL_OPTIONS: &[TtlOption] = &[
    TtlOption {
        label: "1 hour",
        seconds: 3_600,
    },
    TtlOption {
        label: "24 hours",
        seconds: 86_400,
    },
    TtlOption {
        label: "7 days",
        seconds: 604_800,
    },
    TtlOption {
        label: "30 days (max)",
        seconds: MAX_TOKEN_TTL_SECS,
    },
];

/// Current authentication status reported by `GET /api/v1/auth/status`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthStatus {
    pub authenticated: bool,
    pub username: Option<String>,
    pub ssh_host: String,
}

impl Default for AuthStatus {
    fn default() -> Self {
        Self::anonymous(DEFAULT_SSH_HOST)
    }
}

impl AuthStatus {
    /// Constructs an unauthenticated status for the given `ssh_host`.
    #[must_use]
    pub fn anonymous(ssh_host: &str) -> Self {
        Self {
            authenticated: false,
            username: None,
            ssh_host: normalize_ssh_host(ssh_host).to_owned(),
        }
    }

    /// Constructs an authenticated status for `username` and `ssh_host`.
    #[must_use]
    pub fn authenticated(username: &str, ssh_host: &str) -> Self {
        let trimmed = username.trim();
        let host = normalize_ssh_host(ssh_host).to_owned();
        if trimmed.is_empty() {
            Self::anonymous(&host)
        } else {
            Self {
                authenticated: true,
                username: Some(trimmed.to_owned()),
                ssh_host: host,
            }
        }
    }

    /// Formats the human-readable header status label.
    #[must_use]
    pub fn header_label(&self) -> String {
        match (&self.authenticated, self.username.as_deref()) {
            (true, Some(user)) if !user.is_empty() => format!("Signed in as {user}"),
            _ => "Anonymous (public repos only)".to_owned(),
        }
    }
}

/// View-model representation of a single bare Git repository in the index.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct RepositoryItem {
    pub scope: String,
    pub owner: String,
    pub visibility: String,
    pub name: String,
    pub canonical_path: String,
    pub ssh_url: String,
    pub clone_command: String,
}

impl RepositoryItem {
    /// Creates a `RepositoryItem` with formatted canonical path, SSH URL, and `git clone` command.
    #[must_use]
    pub fn new(
        ssh_host: &str,
        authenticated_user: Option<&str>,
        scope: &str,
        owner: &str,
        visibility: &str,
        name: &str,
    ) -> Self {
        let clean_name = strip_git_suffix(name.trim()).to_owned();
        let clean_scope = scope.trim().to_owned();
        let clean_owner = owner.trim().to_owned();
        let clean_visibility = visibility.trim().to_owned();
        let canonical_path = format_canonical_path(
            &clean_scope,
            &clean_owner,
            &clean_visibility,
            &clean_name,
        );
        let ssh_url = format_authenticated_ssh_url(
            ssh_host,
            authenticated_user,
            &clean_scope,
            &clean_owner,
            &clean_visibility,
            &clean_name,
        );
        let clone_command = format_clone_command(
            ssh_host,
            authenticated_user,
            &clean_scope,
            &clean_owner,
            &clean_visibility,
            &clean_name,
        );
        Self {
            scope: clean_scope,
            owner: clean_owner,
            visibility: clean_visibility,
            name: clean_name,
            canonical_path,
            ssh_url,
            clone_command,
        }
    }

    /// Returns the singular badge label (`"user"` or `"team"`) for this repository's scope.
    #[must_use]
    pub fn scope_badge(&self) -> &'static str {
        scope_badge_for(&self.scope)
    }

    /// Returns the visibility badge label (`"public"` or `"private"`).
    #[must_use]
    pub fn visibility_badge(&self) -> &'static str {
        if self.visibility == VISIBILITY_PRIVATE {
            VISIBILITY_PRIVATE
        } else {
            VISIBILITY_PUBLIC
        }
    }

    /// Returns the owner/team namespace prefix (`"/users/<owner>"` or `"/teams/<team>"`).
    #[must_use]
    pub fn group_path(&self) -> String {
        format!("/{}/{}", self.scope, self.owner)
    }

    /// Returns the client-side repository overview route (`"/<scope>/<owner>/<visibility>/<name>"`).
    #[must_use]
    pub fn root_route(&self) -> String {
        format!(
            "/{}/{}/{}/{}",
            self.scope, self.owner, self.visibility, self.name
        )
    }

    /// Converts this item into [`RepoCoordinates`] if all 4 segments are valid.
    #[must_use]
    pub fn coordinates(&self) -> Option<RepoCoordinates> {
        RepoCoordinates::new(&self.scope, &self.owner, &self.visibility, &self.name)
    }

    /// Computes the `ssh://` URL for the given `ssh_host` and optional `authenticated_user`.
    #[must_use]
    pub fn ssh_url_for(&self, ssh_host: &str, authenticated_user: Option<&str>) -> String {
        format_authenticated_ssh_url(
            ssh_host,
            authenticated_user,
            &self.scope,
            &self.owner,
            &self.visibility,
            &self.name,
        )
    }

    /// Computes the `git clone` command for the given `ssh_host` and optional `authenticated_user`.
    #[must_use]
    pub fn clone_command_for(&self, ssh_host: &str, authenticated_user: Option<&str>) -> String {
        format_clone_command(
            ssh_host,
            authenticated_user,
            &self.scope,
            &self.owner,
            &self.visibility,
            &self.name,
        )
    }
}

/// Decoded snapshot from `GET /api/v1/repositories`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepositoriesSnapshot {
    pub repositories: Vec<RepositoryItem>,
    pub authenticated_user: Option<String>,
    pub ssh_host: String,
}

/// Decodes raw Protobuf bytes from `GET /api/v1/auth/status` into an [`AuthStatus`].
pub fn decode_auth_status_response(bytes: &[u8]) -> Result<AuthStatus, String> {
    let view = GetAuthStatusResponseView::from_bytes(bytes)
        .map_err(|e| format!("failed to decode GetAuthStatusResponse: {e:?}"))?;
    let authenticated = view
        .authenticated()
        .map_err(|e| format!("invalid authenticated field: {e:?}"))?;
    let username = view
        .username()
        .map_err(|e| format!("invalid username field: {e:?}"))?
        .trim();
    let ssh_host = view
        .ssh_host()
        .map_err(|e| format!("invalid ssh_host field: {e:?}"))?;

    if authenticated && !username.is_empty() {
        Ok(AuthStatus::authenticated(username, ssh_host))
    } else {
        Ok(AuthStatus::anonymous(ssh_host))
    }
}

/// Decodes raw Protobuf bytes from `GET /api/v1/repositories` into a [`RepositoriesSnapshot`].
pub fn decode_repositories_response(bytes: &[u8]) -> Result<RepositoriesSnapshot, String> {
    let view = ListRepositoriesResponseView::from_bytes(bytes)
        .map_err(|e| format!("failed to decode ListRepositoriesResponse: {e:?}"))?;
    let raw_user = view
        .authenticated_user()
        .map_err(|e| format!("invalid authenticated_user field: {e:?}"))?
        .trim();
    let authenticated_user = (!raw_user.is_empty()).then(|| raw_user.to_owned());
    let raw_host = view
        .ssh_host()
        .map_err(|e| format!("invalid ssh_host field: {e:?}"))?;
    let ssh_host = normalize_ssh_host(raw_host).to_owned();

    let mut repositories = Vec::new();
    for entry in view.repositories() {
        let repo_view = entry.map_err(|e| format!("invalid RepositoryInfo entry: {e:?}"))?;
        let scope = repo_view
            .scope()
            .map_err(|e| format!("invalid scope field: {e:?}"))?;
        let owner = repo_view
            .owner()
            .map_err(|e| format!("invalid owner field: {e:?}"))?;
        let visibility = repo_view
            .visibility()
            .map_err(|e| format!("invalid visibility field: {e:?}"))?;
        let name = repo_view
            .name()
            .map_err(|e| format!("invalid name field: {e:?}"))?;
        let raw_canonical = repo_view
            .canonical_path()
            .map_err(|e| format!("invalid canonical_path field: {e:?}"))?
            .trim();

        let mut item = RepositoryItem::new(
            &ssh_host,
            authenticated_user.as_deref(),
            scope,
            owner,
            visibility,
            name,
        );
        if !raw_canonical.is_empty() {
            item.canonical_path = raw_canonical.to_owned();
        }
        repositories.push(item);
    }

    sort_repositories(&mut repositories);

    Ok(RepositoriesSnapshot {
        repositories,
        authenticated_user,
        ssh_host,
    })
}

#[inline]
#[must_use]
fn scope_badge_for(scope: &str) -> &'static str {
    if scope == SCOPE_USERS {
        "user"
    } else if scope == SCOPE_TEAMS {
        "team"
    } else {
        "repo"
    }
}

#[inline]
#[must_use]
fn scope_sort_rank(scope: &str) -> u8 {
    if scope == SCOPE_USERS {
        0
    } else if scope == SCOPE_TEAMS {
        1
    } else {
        2
    }
}

fn sort_repositories(repos: &mut [RepositoryItem]) {
    repos.sort_by(|a, b| {
        scope_sort_rank(&a.scope)
            .cmp(&scope_sort_rank(&b.scope))
            .then_with(|| a.owner.cmp(&b.owner))
            .then_with(|| a.name.cmp(&b.name))
            .then_with(|| a.visibility.cmp(&b.visibility))
    });
}

/// Top-level scope filter (`All`, `Users`, or `Teams`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ScopeFilter {
    #[default]
    All,
    Users,
    Teams,
}

impl ScopeFilter {
    /// Parses a `<select>` option value into a [`ScopeFilter`].
    #[must_use]
    pub fn from_value(value: &str) -> Self {
        match value.trim() {
            SCOPE_USERS => Self::Users,
            SCOPE_TEAMS => Self::Teams,
            _ => Self::All,
        }
    }

    /// Returns the `<select>` option value string.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::All => "",
            Self::Users => SCOPE_USERS,
            Self::Teams => SCOPE_TEAMS,
        }
    }

    /// Returns the human-readable UI label.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::All => "All Scopes",
            Self::Users => "Users (/users)",
            Self::Teams => "Teams (/teams)",
        }
    }

    /// Returns `true` if `repo_scope` matches this filter.
    #[must_use]
    pub fn matches(self, repo_scope: &str) -> bool {
        match self {
            Self::All => true,
            Self::Users => repo_scope == SCOPE_USERS,
            Self::Teams => repo_scope == SCOPE_TEAMS,
        }
    }
}

/// Repository visibility filter (`All`, `Public`, or `Private`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum VisibilityFilter {
    #[default]
    All,
    Public,
    Private,
}

impl VisibilityFilter {
    /// Parses a `<select>` option value into a [`VisibilityFilter`].
    #[must_use]
    pub fn from_value(value: &str) -> Self {
        match value.trim() {
            VISIBILITY_PUBLIC => Self::Public,
            VISIBILITY_PRIVATE => Self::Private,
            _ => Self::All,
        }
    }

    /// Returns the `<select>` option value string.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::All => "",
            Self::Public => VISIBILITY_PUBLIC,
            Self::Private => VISIBILITY_PRIVATE,
        }
    }

    /// Returns the human-readable UI label.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::All => "All Visibilities",
            Self::Public => "Public",
            Self::Private => "Private",
        }
    }

    /// Returns `true` if `repo_visibility` matches this filter.
    #[must_use]
    pub fn matches(self, repo_visibility: &str) -> bool {
        match self {
            Self::All => true,
            Self::Public => repo_visibility == VISIBILITY_PUBLIC,
            Self::Private => repo_visibility == VISIBILITY_PRIVATE,
        }
    }
}

/// Combined client-side repository filter state.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RepoFilter {
    pub scope: ScopeFilter,
    pub owner: String,
    pub visibility: VisibilityFilter,
    pub query: String,
}

impl RepoFilter {
    /// Returns `true` if no filters or search terms are active.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.scope == ScopeFilter::All
            && self.owner.trim().is_empty()
            && self.visibility == VisibilityFilter::All
            && self.query.trim().is_empty()
    }

    /// Evaluates whether `repo` satisfies all active filter criteria.
    #[must_use]
    pub fn matches(&self, repo: &RepositoryItem) -> bool {
        if !self.scope.matches(&repo.scope) {
            return false;
        }
        if !self.visibility.matches(&repo.visibility) {
            return false;
        }

        let owner_filter = self.owner.trim();
        if !owner_filter.is_empty() {
            let matches_owner = if owner_filter.starts_with('/') {
                repo.group_path().eq_ignore_ascii_case(owner_filter)
            } else {
                repo.owner.eq_ignore_ascii_case(owner_filter)
            };
            if !matches_owner {
                return false;
            }
        }

        let q = self.query.trim();
        if !q.is_empty() {
            let needle = q.to_ascii_lowercase();
            let matches_query = repo.name.to_ascii_lowercase().contains(&needle)
                || repo.owner.to_ascii_lowercase().contains(&needle)
                || repo.canonical_path.to_ascii_lowercase().contains(&needle);
            if !matches_query {
                return false;
            }
        }

        true
    }
}

/// A group of repositories belonging to the same `(scope, owner)` namespace
/// (`/users/<user>` or `/teams/<team>`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepositoryGroup {
    pub scope: String,
    pub owner: String,
    pub group_path: String,
    pub repositories: Vec<RepositoryItem>,
}

impl RepositoryGroup {
    /// Returns the singular badge label (`"user"` or `"team"`) for this group.
    #[must_use]
    pub fn scope_badge(&self) -> &'static str {
        scope_badge_for(&self.scope)
    }
}

/// Returns the sorted, deduplicated list of owner/team names available under `scope`.
#[must_use]
pub fn available_owners(repos: &[RepositoryItem], scope: ScopeFilter) -> Vec<String> {
    let mut owners: Vec<String> = repos
        .iter()
        .filter(|r| scope.matches(&r.scope))
        .map(|r| r.owner.clone())
        .collect();
    owners.sort();
    owners.dedup();
    owners
}

/// Filters `repos` according to `filter`, preserving deterministic order.
#[must_use]
pub fn filter_repositories(repos: &[RepositoryItem], filter: &RepoFilter) -> Vec<RepositoryItem> {
    let mut matched: Vec<RepositoryItem> = repos
        .iter()
        .filter(|repo| filter.matches(repo))
        .cloned()
        .collect();
    sort_repositories(&mut matched);
    matched
}

/// Groups a slice of repositories by `(scope, owner)` (`/users/<user>` and `/teams/<team>`).
#[must_use]
pub fn group_repositories(repos: &[RepositoryItem]) -> Vec<RepositoryGroup> {
    let mut sorted = repos.to_vec();
    sort_repositories(&mut sorted);

    let mut groups: Vec<RepositoryGroup> = Vec::new();
    for repo in sorted {
        if let Some(last) = groups
            .last_mut()
            .filter(|g| g.scope == repo.scope && g.owner == repo.owner)
        {
            last.repositories.push(repo);
        } else {
            let group_path = repo.group_path();
            groups.push(RepositoryGroup {
                scope: repo.scope.clone(),
                owner: repo.owner.clone(),
                group_path,
                repositories: vec![repo],
            });
        }
    }
    groups
}

/// Filters and groups `repos` by `(scope, owner)` in a single pass.
#[must_use]
pub fn filter_and_group_repositories(
    repos: &[RepositoryItem],
    filter: &RepoFilter,
) -> Vec<RepositoryGroup> {
    let filtered = filter_repositories(repos, filter);
    group_repositories(&filtered)
}

/// Computes `now_unix_secs + ttl_secs` while enforcing `1 <= ttl_secs <= MAX_TOKEN_TTL_SECS`.
pub fn compute_expiration_unix(now_unix_secs: u64, ttl_secs: u64) -> Result<u64, TokenError> {
    if ttl_secs == 0 {
        return Err(TokenError::InvalidExpiration);
    }
    if ttl_secs > MAX_TOKEN_TTL_SECS {
        return Err(TokenError::TokenTtlExceeded);
    }
    Ok(now_unix_secs.saturating_add(ttl_secs))
}

/// Prepared SSH signing challenge displayed in the Sign-In modal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignInChallenge {
    pub username: String,
    pub exp_unix_secs: u64,
    pub payload: String,
    pub sign_command: String,
}

/// Builds the timestamped token payload and `ssh-keygen -Y sign` command for `username`.
pub fn build_sign_in_challenge(
    username: &str,
    now_unix_secs: u64,
    ttl_secs: u64,
) -> Result<SignInChallenge, String> {
    let trimmed = username.trim();
    if !is_valid_identifier(trimmed) {
        return Err("Username must be non-empty and match [a-zA-Z0-9_-]+.".to_owned());
    }
    let exp_unix_secs =
        compute_expiration_unix(now_unix_secs, ttl_secs).map_err(|e| e.to_string())?;
    let payload = format_token_payload(trimmed, exp_unix_secs)
        .ok_or_else(|| "Invalid username for token payload.".to_owned())?;
    let sign_command = format_ssh_keygen_sign_command(trimmed, exp_unix_secs)
        .ok_or_else(|| "Failed to format ssh-keygen signing command.".to_owned())?;

    Ok(SignInChallenge {
        username: trimmed.to_owned(),
        exp_unix_secs,
        payload,
        sign_command,
    })
}

/// Validates token claims and encodes `<base64url(payload)>.<base64url(sshsig_pem)>`.
pub fn build_bearer_token_from_signature(
    challenge: &SignInChallenge,
    signature_pem: &str,
    now_unix_secs: u64,
) -> Result<String, String> {
    validate_token_claims(
        &challenge.username,
        challenge.exp_unix_secs,
        now_unix_secs,
        MAX_TOKEN_TTL_SECS,
    )
    .map_err(|e| format!("Token validation failed: {e}"))?;

    encode_bearer_token(&challenge.payload, signature_pem).map_err(|e| match e {
        TokenError::InvalidSignaturePem => {
            "Paste the complete -----BEGIN SSH SIGNATURE----- ... -----END SSH SIGNATURE----- block.".to_owned()
        }
        other => format!("Failed to encode bearer token: {other}"),
    })
}

/// Verifies that an [`AuthStatus`] returned by `GET /api/v1/auth/status` confirms
/// authentication for `expected_username`.
pub fn verify_auth_status_for_user(
    status: &AuthStatus,
    expected_username: &str,
) -> Result<(), String> {
    let expected = expected_username.trim();
    if !status.authenticated {
        return Err(
            "SSH signature verification failed: server rejected the bearer token (check your username and ~/.ssh/id_ed25519 key in authorized_keys).".to_owned(),
        );
    }
    match status.username.as_deref() {
        Some(actual) if actual == expected => Ok(()),
        Some(actual) => Err(format!(
            "Authenticated user '{actual}' does not match requested username '{expected}'."
        )),
        None => Err("Server returned authenticated status without a username.".to_owned()),
    }
}

/// Formats an HTTP `Authorization` header value (`"Bearer <token>"`) if `token` is non-empty.
#[must_use]
pub fn format_authorization_header(token: &str) -> Option<String> {
    let trimmed = token.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("bearer") {
        return None;
    }
    if trimmed.len() >= 7
        && trimmed.as_bytes()[..6].eq_ignore_ascii_case(b"bearer")
        && trimmed.as_bytes()[6].is_ascii_whitespace()
    {
        let raw = trimmed[7..].trim();
        (!raw.is_empty()).then(|| format!("Bearer {raw}"))
    } else {
        Some(format!("Bearer {trimmed}"))
    }
}

/// Identifies which copy-to-clipboard button most recently succeeded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CopyTarget {
    CloneCommand(String),
    SshUrl(String),
    SignCommand,
}

/// Returns `"Copied!"` when `active_target` matches `button_target`, or `default_label` otherwise.
#[must_use]
pub fn copy_button_label<'a>(
    active_target: Option<&CopyTarget>,
    button_target: &CopyTarget,
    default_label: &'a str,
) -> &'a str {
    if active_target == Some(button_target) {
        "Copied!"
    } else {
        default_label
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ro_git_proto::ro_git::v1::{GetAuthStatusResponseBuilder, ListRepositoriesResponseBuilder};
    use ro_git_proto:: decode_bearer_token;

    const SAMPLE_SSHSIG_PEM: &str = "-----BEGIN SSH SIGNATURE-----\n\
U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAg8f7/7f39/f39/f39/f39\n\
/f39/f39/f39/f39/f39/f0AAAAGcm8tZ2l0AAAAAAAAAAZzaGE1MTIAAABTAAAA\n\
C3NzaC1lZDI1NTE5AAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==\n\
-----END SSH SIGNATURE-----";

    fn sample_repositories(ssh_host: &str, auth_user: Option<&str>) -> Vec<RepositoryItem> {
        vec![
            RepositoryItem::new(ssh_host, auth_user, "teams", "core", "private", "infra.git"),
            RepositoryItem::new(ssh_host, auth_user, "users", "bob", "public", "cli"),
            RepositoryItem::new(ssh_host, auth_user, "users", "alice", "private", "secrets"),
            RepositoryItem::new(ssh_host, auth_user, "users", "alice", "public", "dotfiles"),
            RepositoryItem::new(ssh_host, auth_user, "teams", "core", "public", "handbook"),
        ]
    }

    #[test]
    fn auth_status_constructors_and_header_labels() {
        let anon = AuthStatus::default();
        assert!(!anon.authenticated);
        assert_eq!(anon.username, None);
        assert_eq!(anon.ssh_host, "localhost");
        assert_eq!(anon.header_label(), "Anonymous (public repos only)");

        let auth = AuthStatus::authenticated("alice", "ssh://git.example.com:2222/");
        assert!(auth.authenticated);
        assert_eq!(auth.username.as_deref(), Some("alice"));
        assert_eq!(auth.ssh_host, "git.example.com:2222");
        assert_eq!(auth.header_label(), "Signed in as alice");

        let blank_user = AuthStatus::authenticated("   ", "git.example.com");
        assert!(!blank_user.authenticated);
        assert_eq!(blank_user.username, None);
        assert_eq!(blank_user.header_label(), "Anonymous (public repos only)");
    }

    #[test]
    fn decodes_auth_status_protobuf_responses() {
        let mut buf = [0u8; 256];
        let mut builder = GetAuthStatusResponseBuilder::new(&mut buf);
        builder
            .write_ssh_host("git.internal:2222")
            .write_username("charles")
            .write_authenticated(true);
        let bytes = builder.finish().expect("encode authenticated status");

        let decoded = decode_auth_status_response(bytes).expect("decode auth status");
        assert!(decoded.authenticated);
        assert_eq!(decoded.username.as_deref(), Some("charles"));
        assert_eq!(decoded.ssh_host, "git.internal:2222");
        assert_eq!(decoded.header_label(), "Signed in as charles");

        // Unauthenticated response
        let mut anon_buf = [0u8; 128];
        let mut anon_builder = GetAuthStatusResponseBuilder::new(&mut anon_buf);
        anon_builder
            .write_ssh_host("git.internal")
            .write_authenticated(false);
        let anon_bytes = anon_builder.finish().expect("encode anon status");

        let anon_decoded = decode_auth_status_response(anon_bytes).expect("decode anon status");
        assert!(!anon_decoded.authenticated);
        assert_eq!(anon_decoded.username, None);
        assert_eq!(anon_decoded.ssh_host, "git.internal");

        // Truncated wire bytes fail cleanly
        assert!(decode_auth_status_response(&[0x0a, 0xff]).is_err());
    }

    #[test]
    fn decodes_repositories_protobuf_responses_and_sorts_deterministically() {
        let fixtures = [
            ("teams", "core", "private", "ro-git"),
            ("users", "alice", "public", "dotfiles.git"),
        ];

        let mut buf = [0u8; 1024];
        let mut builder = ListRepositoriesResponseBuilder::new(&mut buf);
        builder
            .write_ssh_host("ssh://git.example.org/")
            .write_authenticated_user("alice");

        for &(scope, owner, vis, name) in fixtures.iter().rev() {
            let canonical = format_canonical_path(scope, owner, vis, name);
            builder.write_repositories(|repo| {
                repo.write_canonical_path(&canonical)
                    .write_name(name)
                    .write_visibility(vis)
                    .write_owner(owner)
                    .write_scope(scope);
            });
            builder.check().expect("buffer capacity");
        }

        let bytes = builder.finish().expect("encode ListRepositoriesResponse");
        let snapshot = decode_repositories_response(bytes).expect("decode repositories");
        assert_eq!(snapshot.ssh_host, "git.example.org");
        assert_eq!(snapshot.authenticated_user.as_deref(), Some("alice"));
        assert_eq!(snapshot.repositories.len(), 2);

        // Sorted: users before teams
        let first = &snapshot.repositories[0];
        assert_eq!(first.scope, "users");
        assert_eq!(first.owner, "alice");
        assert_eq!(first.visibility, "public");
        assert_eq!(first.name, "dotfiles");
        assert_eq!(first.canonical_path, "/users/alice/public/dotfiles.git");
        assert_eq!(
            first.ssh_url,
            "ssh://alice@git.example.org/users/alice/public/dotfiles.git"
        );
        assert_eq!(
            first.clone_command,
            "git clone ssh://alice@git.example.org/users/alice/public/dotfiles.git"
        );

        let second = &snapshot.repositories[1];
        assert_eq!(second.scope, "teams");
        assert_eq!(second.owner, "core");
        assert_eq!(second.visibility, "private");
        assert_eq!(second.name, "ro-git");
        assert_eq!(second.canonical_path, "/teams/core/private/ro-git.git");
        assert_eq!(
            second.ssh_url,
            "ssh://alice@git.example.org/teams/core/private/ro-git.git"
        );
        assert_eq!(
            second.clone_command,
            "git clone ssh://alice@git.example.org/teams/core/private/ro-git.git"
        );

        // Invalid wire bytes fail cleanly
        assert!(decode_repositories_response(&[0x0a, 0x99]).is_err());
    }

    #[test]
    fn formats_repository_item_badges_urls_and_clone_commands() {
        let anon_repo = RepositoryItem::new(
            "git.example.com",
            None,
            "users",
            "alice",
            "public",
            "notes.git",
        );
        assert_eq!(anon_repo.name, "notes");
        assert_eq!(anon_repo.scope_badge(), "user");
        assert_eq!(anon_repo.visibility_badge(), "public");
        assert_eq!(anon_repo.group_path(), "/users/alice");
        assert_eq!(
            anon_repo.canonical_path,
            "/users/alice/public/notes.git"
        );
        assert_eq!(
            anon_repo.ssh_url,
            "ssh://git.example.com/users/alice/public/notes.git"
        );
        assert_eq!(
            anon_repo.clone_command,
            "git clone ssh://git.example.com/users/alice/public/notes.git"
        );
        assert_eq!(
            anon_repo.ssh_url_for("git.example.com", Some("alice")),
            "ssh://alice@git.example.com/users/alice/public/notes.git"
        );
        assert_eq!(
            anon_repo.clone_command_for("git.example.com", Some("alice")),
            "git clone ssh://alice@git.example.com/users/alice/public/notes.git"
        );

        let team_repo = RepositoryItem::new(
            "git.example.com:2222",
            Some("bob"),
            "teams",
            "platform",
            "private",
            "deploy",
        );
        assert_eq!(team_repo.scope_badge(), "team");
        assert_eq!(team_repo.visibility_badge(), "private");
        assert_eq!(team_repo.group_path(), "/teams/platform");
        assert_eq!(
            team_repo.ssh_url,
            "ssh://bob@git.example.com:2222/teams/platform/private/deploy.git"
        );
        assert_eq!(
            team_repo.clone_command,
            "git clone ssh://bob@git.example.com:2222/teams/platform/private/deploy.git"
        );
    }

    #[test]
    fn filters_and_groups_repositories_by_scope_owner_visibility_and_query() {
        let repos = sample_repositories("localhost", None);

        assert_eq!(
            available_owners(&repos, ScopeFilter::All),
            vec!["alice".to_owned(), "bob".to_owned(), "core".to_owned()]
        );
        assert_eq!(
            available_owners(&repos, ScopeFilter::Users),
            vec!["alice".to_owned(), "bob".to_owned()]
        );
        assert_eq!(
            available_owners(&repos, ScopeFilter::Teams),
            vec!["core".to_owned()]
        );

        // Default empty filter returns 3 groups: /users/alice, /users/bob, /teams/core
        let default_filter = RepoFilter::default();
        assert!(default_filter.is_empty());
        let all_groups = filter_and_group_repositories(&repos, &default_filter);
        assert_eq!(all_groups.len(), 3);
        assert_eq!(all_groups[0].group_path, "/users/alice");
        assert_eq!(all_groups[0].scope_badge(), "user");
        assert_eq!(all_groups[0].repositories.len(), 2);
        assert_eq!(all_groups[0].repositories[0].name, "dotfiles");
        assert_eq!(all_groups[0].repositories[1].name, "secrets");
        assert_eq!(all_groups[1].group_path, "/users/bob");
        assert_eq!(all_groups[1].repositories.len(), 1);
        assert_eq!(all_groups[2].group_path, "/teams/core");
        assert_eq!(all_groups[2].scope_badge(), "team");
        assert_eq!(all_groups[2].repositories.len(), 2);

        // Filter by scope = Teams
        let team_filter = RepoFilter {
            scope: ScopeFilter::from_value("teams"),
            ..RepoFilter::default()
        };
        assert!(!team_filter.is_empty());
        let team_groups = filter_and_group_repositories(&repos, &team_filter);
        assert_eq!(team_groups.len(), 1);
        assert_eq!(team_groups[0].group_path, "/teams/core");

        // Filter by owner = alice and visibility = private
        let alice_private_filter = RepoFilter {
            scope: ScopeFilter::Users,
            owner: "ALICE".to_owned(),
            visibility: VisibilityFilter::from_value("private"),
            query: String::new(),
        };
        let alice_private = filter_repositories(&repos, &alice_private_filter);
        assert_eq!(alice_private.len(), 1);
        assert_eq!(alice_private[0].name, "secrets");

        // Filter by group path prefix in owner field
        let group_owner_filter = RepoFilter {
            owner: "/teams/core".to_owned(),
            ..RepoFilter::default()
        };
        assert_eq!(filter_repositories(&repos, &group_owner_filter).len(), 2);

        // Filter by search query matching canonical path or repo name
        let query_filter = RepoFilter {
            query: "core/public".to_owned(),
            ..RepoFilter::default()
        };
        let queried = filter_repositories(&repos, &query_filter);
        assert_eq!(queried.len(), 1);
        assert_eq!(queried[0].name, "handbook");
    }

    #[test]
    fn scope_and_visibility_filter_conversions() {
        assert_eq!(ScopeFilter::from_value(""), ScopeFilter::All);
        assert_eq!(ScopeFilter::from_value("users"), ScopeFilter::Users);
        assert_eq!(ScopeFilter::from_value("teams"), ScopeFilter::Teams);
        assert_eq!(ScopeFilter::All.as_str(), "");
        assert_eq!(ScopeFilter::Users.as_str(), "users");
        assert_eq!(ScopeFilter::Teams.as_str(), "teams");
        assert_eq!(ScopeFilter::All.label(), "All Scopes");
        assert_eq!(ScopeFilter::Users.label(), "Users (/users)");
        assert_eq!(ScopeFilter::Teams.label(), "Teams (/teams)");

        assert_eq!(VisibilityFilter::from_value(""), VisibilityFilter::All);
        assert_eq!(
            VisibilityFilter::from_value("public"),
            VisibilityFilter::Public
        );
        assert_eq!(
            VisibilityFilter::from_value("private"),
            VisibilityFilter::Private
        );
        assert_eq!(VisibilityFilter::All.as_str(), "");
        assert_eq!(VisibilityFilter::Public.as_str(), "public");
        assert_eq!(VisibilityFilter::Private.as_str(), "private");
        assert_eq!(VisibilityFilter::All.label(), "All Visibilities");
        assert_eq!(VisibilityFilter::Public.label(), "Public");
        assert_eq!(VisibilityFilter::Private.label(), "Private");
    }

    #[test]
    fn builds_and_validates_ssh_sign_in_challenge_and_bearer_token() {
        let now = 1_700_000_000;
        let challenge =
            build_sign_in_challenge("  charles_01 ", now, DEFAULT_TTL_SECS).expect("valid challenge");
        assert_eq!(challenge.username, "charles_01");
        assert_eq!(challenge.exp_unix_secs, now + DEFAULT_TTL_SECS);
        assert_eq!(challenge.payload, "ro-git:v1:charles_01:1700086400");
        assert_eq!(
            challenge.sign_command,
            "printf 'ro-git:v1:charles_01:1700086400' | ssh-keygen -Y sign -f ~/.ssh/id_ed25519 -n ro-git"
        );

        let token = build_bearer_token_from_signature(&challenge, SAMPLE_SSHSIG_PEM, now)
            .expect("encode bearer token");
        let decoded = decode_bearer_token(&token).expect("decode bearer token");
        assert_eq!(decoded.username, "charles_01");
        assert_eq!(decoded.exp_unix_secs, now + DEFAULT_TTL_SECS);

        // Verify auth status matching user
        let status_ok = AuthStatus::authenticated("charles_01", "localhost");
        assert!(verify_auth_status_for_user(&status_ok, "charles_01").is_ok());

        // Rejects unauthenticated or mismatched user
        let status_anon = AuthStatus::anonymous("localhost");
        assert!(verify_auth_status_for_user(&status_anon, "charles_01").is_err());
        let status_other = AuthStatus::authenticated("mallory", "localhost");
        assert!(verify_auth_status_for_user(&status_other, "charles_01").is_err());

        // Rejects invalid username, zero TTL, excessive TTL, or bad PEM
        assert!(build_sign_in_challenge("", now, DEFAULT_TTL_SECS).is_err());
        assert!(build_sign_in_challenge("bad/user", now, DEFAULT_TTL_SECS).is_err());
        assert_eq!(
            compute_expiration_unix(now, 0),
            Err(TokenError::InvalidExpiration)
        );
        assert_eq!(
            compute_expiration_unix(now, MAX_TOKEN_TTL_SECS + 1),
            Err(TokenError::TokenTtlExceeded)
        );
        assert!(build_bearer_token_from_signature(&challenge, "not a pem", now).is_err());
        assert!(
            build_bearer_token_from_signature(&challenge, SAMPLE_SSHSIG_PEM, challenge.exp_unix_secs)
                .is_err()
        );
    }

    #[test]
    fn formats_authorization_header_and_copy_labels() {
        assert_eq!(format_authorization_header(""), None);
        assert_eq!(format_authorization_header("   "), None);
        assert_eq!(format_authorization_header("Bearer   "), None);
        assert_eq!(
            format_authorization_header("abc.def"),
            Some("Bearer abc.def".to_owned())
        );
        assert_eq!(
            format_authorization_header("  bearer abc.def  "),
            Some("Bearer abc.def".to_owned())
        );

        let clone_target = CopyTarget::CloneCommand("/users/alice/public/notes.git".to_owned());
        let ssh_target = CopyTarget::SshUrl("/users/alice/public/notes.git".to_owned());
        assert_eq!(
            copy_button_label(Some(&clone_target), &clone_target, "Copy git clone"),
            "Copied!"
        );
        assert_eq!(
            copy_button_label(Some(&clone_target), &ssh_target, "Copy SSH URL"),
            "Copy SSH URL"
        );
        assert_eq!(
            copy_button_label(None, &CopyTarget::SignCommand, "Copy Command"),
            "Copy Command"
        );
    }
}
