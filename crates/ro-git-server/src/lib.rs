//! `ro-git-server` backend library implementing the `roto-grpc` `GitService`,
//! OpenSSH `SSHSIG` stateless token verification, user/team credential resolution,
//! and privilege-separated `git-worker` IPC and repository discovery.

#![deny(unsafe_code)]

use std::fmt;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ro_git_proto::grpc::ro_git::v1::git_service::{GitService, GitServiceServer};
use ro_git_proto::ro_git::v1::{
    worker_request, worker_response, GetAuthStatusRequestView, GetAuthStatusResponseBuilder,
    GetAuthStatusResponseView, GetBlobRequestBuilder, GetBlobRequestView, GetBlobResponseBuilder,
    GetBlobResponseView, GetCommitRequestBuilder, GetCommitRequestView, GetCommitResponseBuilder,
    GetCommitResponseView, GetRepositoryRequestBuilder, GetRepositoryRequestView,
    GetRepositoryResponseBuilder, GetRepositoryResponseView, GetTreeRequestBuilder,
    GetTreeRequestView, GetTreeResponseBuilder, GetTreeResponseView, ListCommitsRequestBuilder,
    ListCommitsRequestView, ListCommitsResponseBuilder, ListCommitsResponseView,
    ListRepositoriesRequestBuilder, ListRepositoriesRequestView, ListRepositoriesResponseBuilder,
    ListRepositoriesResponseView, RepositoryInfoBuilder, WorkerRequestBuilder, WorkerRequestView,
    WorkerResponseBuilder, WorkerResponseView,
};
use ro_git_proto::{
    decode_bearer_token, format_canonical_path, format_clone_command, format_ssh_url,
    is_valid_identifier, is_valid_scope, is_valid_visibility, normalize_ssh_host,
    validate_token_claims, TokenError, API_AUTH_STATUS_PATH, API_REPOSITORIES_PATH, SCOPE_TEAMS,
    SCOPE_USERS, SSH_SIG_NAMESPACE, VISIBILITY_PRIVATE, VISIBILITY_PUBLIC,
};
use roto::runtime::BackwardWriter;
use roto_grpc::http::{
    finish_writer_response, http_reason_phrase, percent_decode_str, HttpMethod, HttpRequest,
    HttpResponse, HttpService, QueryIter,
};
use roto_grpc::{
    DynamicMetadata, GrpcCode, GrpcServer, GrpcService, GrpcStatus, Route, RpcContext, RpcMetadata,
};
use ssh_key::{PublicKey, SshSig};

pub mod git_reader;
pub use git_reader::*;

/// Server configuration resolved from environment variables.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerConfig {
    pub listen_addr: String,
    pub root_dir: String,
    pub ssh_host: String,
    pub static_dir: String,
    pub max_token_ttl_secs: u64,
    pub nobody_uid: u32,
    pub dev_user: Option<String>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen_addr: String::from("0.0.0.0:8080"),
            root_dir: String::from("/"),
            ssh_host: String::from("localhost"),
            static_dir: String::from("/app/dist"),
            max_token_ttl_secs: 2_592_000,
            nobody_uid: 65_534,
            dev_user: None,
        }
    }
}

impl ServerConfig {
    /// Loads server configuration from `RO_GIT_*` environment variables with defaults.
    #[must_use]
    pub fn from_env() -> Self {
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    /// Resolves server configuration using a custom environment lookup function,
    /// trimming surrounding whitespace and falling back to defaults on empty or invalid values.
    #[must_use]
    pub fn from_lookup<F>(lookup: F) -> Self
    where
        F: Fn(&str) -> Option<String>,
    {
        let non_empty = |key: &str| -> Option<String> {
            lookup(key)
                .map(|v| v.trim().to_owned())
                .filter(|v| !v.is_empty())
        };

        let mut cfg = Self::default();
        if let Some(val) = non_empty("RO_GIT_LISTEN_ADDR") {
            cfg.listen_addr = val;
        }
        if let Some(val) = non_empty("RO_GIT_ROOT") {
            cfg.root_dir = val;
        }
        if let Some(val) = non_empty("RO_GIT_SSH_HOST") {
            cfg.ssh_host = val;
        }
        if let Some(val) = non_empty("RO_GIT_STATIC_DIR") {
            cfg.static_dir = val;
        }
        if let Some(parsed) = non_empty("RO_GIT_MAX_TOKEN_TTL_SECS").and_then(|v| v.parse().ok()) {
            cfg.max_token_ttl_secs = parsed;
        }
        if let Some(parsed) = non_empty("RO_GIT_NOBODY_UID").and_then(|v| v.parse().ok()) {
            cfg.nobody_uid = parsed;
        }
        cfg.dev_user = non_empty("RO_GIT_DEV_USER");
        cfg
    }
}

/// Authentication, signature verification, and credential resolution errors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthError {
    Token(TokenError),
    InvalidUsername,
    UserNotFound,
    UnsafeAuthorizedKeys(String),
    AuthorizedKeysIo(String),
    InvalidAuthorizedKeyLine(String),
    InvalidSignatureFormat,
    InvalidSignatureNamespace(String),
    SignatureVerificationFailed,
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Token(err) => write!(f, "{err}"),
            Self::InvalidUsername => f.write_str("invalid username identifier"),
            Self::UserNotFound => f.write_str("user directory not found"),
            Self::UnsafeAuthorizedKeys(msg) => write!(f, "unsafe authorized_keys: {msg}"),
            Self::AuthorizedKeysIo(msg) => write!(f, "failed to read authorized_keys: {msg}"),
            Self::InvalidAuthorizedKeyLine(msg) => {
                write!(f, "invalid authorized_keys entry: {msg}")
            }
            Self::InvalidSignatureFormat => f.write_str("invalid OpenSSH signature format"),
            Self::InvalidSignatureNamespace(ns) => {
                write!(f, "invalid SSH signature namespace '{ns}'")
            }
            Self::SignatureVerificationFailed => {
                f.write_str("SSH signature verification failed against authorized_keys")
            }
        }
    }
}

impl From<TokenError> for AuthError {
    fn from(err: TokenError) -> Self {
        Self::Token(err)
    }
}

/// Resolved OS credentials and team memberships for privilege-separated worker execution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserCredentials {
    pub username: Option<String>,
    pub uid: u32,
    pub gid: u32,
    pub supplementary_gids: Vec<u32>,
    pub team_names: Vec<String>,
}

/// Discovered bare Git repository metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscoveredRepository {
    pub scope: String,
    pub owner: String,
    pub visibility: String,
    pub name: String,
    pub canonical_path: String,
    pub ssh_url: String,
    pub clone_command: String,
}

impl DiscoveredRepository {
    pub(crate) fn encode_into(&self, r: &mut RepositoryInfoBuilder<'_>) {
        r.write_clone_command(&self.clone_command)
            .write_ssh_url(&self.ssh_url)
            .write_canonical_path(&self.canonical_path)
            .write_name(&self.name)
            .write_visibility(&self.visibility)
            .write_owner(&self.owner)
            .write_scope(&self.scope);
    }
}

/// Repository filter parameters for `ListRepositories`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RepositoryFilter<'a> {
    pub scope: &'a str,
    pub owner: &'a str,
    pub visibility: &'a str,
    pub query: &'a str,
}

/// Parses a single line from an OpenSSH `authorized_keys` file, ignoring blank lines
/// and `#` comments and stripping optional leading `authorized_keys` options (including
/// quoted option values).
pub fn parse_authorized_keys_line(line: &str) -> Result<Option<PublicKey>, AuthError> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return Ok(None);
    }

    if let Ok(pubkey) = PublicKey::from_openssh(trimmed) {
        return Ok(Some(pubkey));
    }

    if let Some(rest) = skip_authorized_keys_options(trimmed) {
        if let Ok(pubkey) = PublicKey::from_openssh(rest) {
            return Ok(Some(pubkey));
        }
    }

    Err(AuthError::InvalidAuthorizedKeyLine(String::from(
        "unrecognized public key format",
    )))
}

fn skip_authorized_keys_options(line: &str) -> Option<&str> {
    let bytes = line.as_bytes();
    let mut in_quotes = false;
    let mut escaped = false;
    let mut idx = 0;

    while idx < bytes.len() {
        let b = bytes[idx];
        if escaped {
            escaped = false;
        } else if b == b'\\' && in_quotes {
            escaped = true;
        } else if b == b'"' {
            in_quotes = !in_quotes;
        } else if !in_quotes && b.is_ascii_whitespace() {
            let rest = line[idx..].trim_start();
            return if rest.is_empty() { None } else { Some(rest) };
        }
        idx += 1;
    }
    None
}

/// Loads and validates `/users/<username>/authorized_keys` under `root_dir`.
///
/// Rejects symlinked user directories, symlinked `authorized_keys` files, non-regular
/// files, and unsafe permission modes (only `0600` or `0640` are permitted).
pub fn load_user_authorized_keys(
    root_dir: &Path,
    username: &str,
) -> Result<Vec<PublicKey>, AuthError> {
    if !is_valid_identifier(username) {
        return Err(AuthError::InvalidUsername);
    }

    let user_dir = root_dir.join(SCOPE_USERS).join(username);
    let user_meta = fs::symlink_metadata(&user_dir).map_err(|_| AuthError::UserNotFound)?;
    if user_meta.file_type().is_symlink() {
        return Err(AuthError::UnsafeAuthorizedKeys(String::from(
            "user directory must not be a symlink",
        )));
    }
    if !user_meta.is_dir() {
        return Err(AuthError::UserNotFound);
    }

    let auth_keys_path = user_dir.join("authorized_keys");
    let key_meta = fs::symlink_metadata(&auth_keys_path).map_err(|err| {
        AuthError::AuthorizedKeysIo(format!("cannot stat authorized_keys: {err}"))
    })?;
    if key_meta.file_type().is_symlink() {
        return Err(AuthError::UnsafeAuthorizedKeys(String::from(
            "authorized_keys must not be a symlink",
        )));
    }
    if !key_meta.is_file() {
        return Err(AuthError::UnsafeAuthorizedKeys(String::from(
            "authorized_keys must be a regular file",
        )));
    }

    let mode = key_meta.permissions().mode() & 0o777;
    if mode != 0o600 && mode != 0o640 {
        return Err(AuthError::UnsafeAuthorizedKeys(format!(
            "authorized_keys mode {mode:04o} is not 0600 or 0640"
        )));
    }

    let contents = fs::read_to_string(&auth_keys_path).map_err(|err| {
        AuthError::AuthorizedKeysIo(format!("cannot read authorized_keys: {err}"))
    })?;

    let mut keys = Vec::new();
    for line in contents.lines() {
        if let Some(pk) = parse_authorized_keys_line(line)? {
            keys.push(pk);
        }
    }

    if keys.is_empty() {
        return Err(AuthError::SignatureVerificationFailed);
    }

    Ok(keys)
}

/// Verifies a stateless `<base64url(payload)>.<base64url(sshsig_pem)>` bearer token
/// against `/users/<user>/authorized_keys` under `root_dir`, returning the authenticated
/// username on success.
pub fn verify_bearer_token(
    root_dir: &Path,
    token: &str,
    now_unix_secs: u64,
    max_token_ttl_secs: u64,
) -> Result<String, AuthError> {
    let decoded = decode_bearer_token(token)?;
    validate_token_claims(
        &decoded.username,
        decoded.exp_unix_secs,
        now_unix_secs,
        max_token_ttl_secs,
    )?;

    let sshsig = SshSig::from_pem(decoded.sshsig_pem.as_bytes())
        .map_err(|_| AuthError::InvalidSignatureFormat)?;
    if sshsig.namespace() != SSH_SIG_NAMESPACE {
        return Err(AuthError::InvalidSignatureNamespace(
            sshsig.namespace().to_owned(),
        ));
    }

    let authorized_keys = load_user_authorized_keys(root_dir, &decoded.username)?;
    let payload_bytes = decoded.payload.as_bytes();

    let verified = authorized_keys.iter().any(|pubkey| {
        pubkey.key_data() == sshsig.public_key()
            && pubkey
                .verify(SSH_SIG_NAMESPACE, payload_bytes, &sshsig)
                .is_ok()
    });

    if !verified {
        return Err(AuthError::SignatureVerificationFailed);
    }

    Ok(decoded.username)
}

fn default_etc_dir(root_dir: &Path) -> PathBuf {
    if let Ok(val) = std::env::var("RO_GIT_ETC_DIR") {
        let trimmed = val.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }
    let candidate = root_dir.join("etc");
    if candidate.join("passwd").exists() || candidate.join("group").exists() {
        return candidate;
    }
    PathBuf::from("/etc")
}

/// Resolves OS UID, primary GID, supplementary GIDs, and team names for an authenticated
/// user or anonymous (`nobody_uid`) request.
pub fn resolve_user_credentials(
    root_dir: &Path,
    etc_dir: Option<&Path>,
    username: Option<&str>,
    nobody_uid: u32,
) -> Result<UserCredentials, AuthError> {
    let Some(user) = username.map(str::trim).filter(|u| !u.is_empty()) else {
        return Ok(UserCredentials {
            username: None,
            uid: nobody_uid,
            gid: nobody_uid,
            supplementary_gids: Vec::new(),
            team_names: Vec::new(),
        });
    };

    if !is_valid_identifier(user) {
        return Err(AuthError::InvalidUsername);
    }

    let user_dir = root_dir.join(SCOPE_USERS).join(user);
    let user_meta = match fs::symlink_metadata(&user_dir) {
        Ok(meta) => {
            if meta.file_type().is_symlink() || !meta.is_dir() {
                return Err(AuthError::UserNotFound);
            }
            Some(meta)
        }
        Err(_) => None,
    };

    let resolved_etc = etc_dir
        .map(Path::to_path_buf)
        .unwrap_or_else(|| default_etc_dir(root_dir));

    let passwd_ids = lookup_passwd_uid_gid(&resolved_etc.join("passwd"), user);
    let (uid, gid) = match (passwd_ids, user_meta) {
        (Some((u, g)), _) => (u, g),
        (None, Some(meta)) => (meta.uid(), meta.gid()),
        (None, None) => return Err(AuthError::UserNotFound),
    };

    let mut supplementary_gids = Vec::new();
    let mut team_names = Vec::new();

    if let Some((group_gids, group_teams)) =
        lookup_supplementary_groups(&resolved_etc.join("group"), user, gid)
    {
        for g in group_gids {
            if g != gid && !supplementary_gids.contains(&g) {
                supplementary_gids.push(g);
            }
        }
        for t in group_teams {
            if !team_names.contains(&t) {
                team_names.push(t);
            }
        }
    }

    // Also inspect `<root_dir>/teams/<team>/members` so team memberships and GIDs
    // are always resolved accurately from the repository hierarchy.
    collect_filesystem_team_memberships(
        root_dir,
        user,
        gid,
        &mut supplementary_gids,
        &mut team_names,
    );

    supplementary_gids.sort_unstable();
    team_names.sort();

    Ok(UserCredentials {
        username: Some(user.to_owned()),
        uid,
        gid,
        supplementary_gids,
        team_names,
    })
}

fn is_non_symlink_dir(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|meta| !meta.file_type().is_symlink() && meta.is_dir())
        .unwrap_or(false)
}

fn is_non_symlink_dir_entry(entry: &fs::DirEntry) -> bool {
    entry
        .file_type()
        .map(|ft| !ft.is_symlink() && ft.is_dir())
        .unwrap_or(false)
}

fn collect_filesystem_team_memberships(
    root_dir: &Path,
    username: &str,
    primary_gid: u32,
    supplementary_gids: &mut Vec<u32>,
    team_names: &mut Vec<String>,
) {
    let teams_dir = root_dir.join(SCOPE_TEAMS);
    if !is_non_symlink_dir(&teams_dir) {
        return;
    }
    let Ok(entries) = fs::read_dir(&teams_dir) else {
        return;
    };

    for entry in entries.flatten() {
        if !is_non_symlink_dir_entry(&entry) {
            continue;
        }
        let fname = entry.file_name();
        let Some(team_name) = fname.to_str() else {
            continue;
        };
        if !is_valid_identifier(team_name) {
            continue;
        }
        if !is_user_in_team_members_file(&entry.path().join("members"), username) {
            continue;
        }
        if team_names.iter().any(|t| t == team_name) {
            continue;
        }

        team_names.push(team_name.to_owned());
        if let Ok(team_meta) = fs::symlink_metadata(entry.path()) {
            let team_gid = team_meta.gid();
            if team_gid != primary_gid && !supplementary_gids.contains(&team_gid) {
                supplementary_gids.push(team_gid);
            }
        }
    }
}

#[allow(unsafe_code)]
fn resolve_or_fallback_dev_credentials(
    root_dir: &Path,
    etc_dir: Option<&Path>,
    username: &str,
    nobody_uid: u32,
) -> Result<UserCredentials, AuthError> {
    if !is_valid_identifier(username) {
        return Err(AuthError::InvalidUsername);
    }
    Ok(
        resolve_user_credentials(root_dir, etc_dir, Some(username), nobody_uid).unwrap_or_else(
            |_| {
                // SAFETY: `geteuid` and `getegid` are thread-safe POSIX syscalls with no preconditions.
                let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
                UserCredentials {
                    username: Some(username.to_owned()),
                    uid,
                    gid,
                    supplementary_gids: Vec::new(),
                    team_names: Vec::new(),
                }
            },
        ),
    )
}

fn lookup_passwd_uid_gid(passwd_path: &Path, username: &str) -> Option<(u32, u32)> {
    let meta = fs::symlink_metadata(passwd_path).ok()?;
    if meta.file_type().is_symlink() || !meta.is_file() {
        return None;
    }
    let contents = fs::read_to_string(passwd_path).ok()?;
    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let mut fields = trimmed.split(':');
        let name = fields.next()?;
        let _passwd = fields.next()?;
        let uid_str = fields.next()?;
        let gid_str = fields.next()?;
        if name == username {
            let uid = uid_str.parse::<u32>().ok()?;
            let gid = gid_str.parse::<u32>().ok()?;
            return Some((uid, gid));
        }
    }
    None
}

fn lookup_supplementary_groups(
    group_path: &Path,
    username: &str,
    primary_gid: u32,
) -> Option<(Vec<u32>, Vec<String>)> {
    let meta = fs::symlink_metadata(group_path).ok()?;
    if meta.file_type().is_symlink() || !meta.is_file() {
        return None;
    }
    let contents = fs::read_to_string(group_path).ok()?;
    let mut gids = Vec::new();
    let mut teams = Vec::new();

    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let mut fields = trimmed.split(':');
        let Some(group_name) = fields.next() else {
            continue;
        };
        let Some(_passwd) = fields.next() else {
            continue;
        };
        let Some(gid_str) = fields.next() else {
            continue;
        };
        let Ok(gid) = gid_str.parse::<u32>() else {
            continue;
        };
        let members_field = fields.next().unwrap_or("");
        let is_member = gid == primary_gid
            || members_field
                .split(',')
                .map(str::trim)
                .any(|m| !m.is_empty() && m == username);
        if is_member {
            if !gids.contains(&gid) {
                gids.push(gid);
            }
            if let Some(team) = group_name.strip_prefix("team-") {
                if is_valid_identifier(team) && !teams.iter().any(|t| t == team) {
                    teams.push(team.to_owned());
                }
            }
        }
    }

    Some((gids, teams))
}

fn is_user_in_team_members_file(members_path: &Path, username: &str) -> bool {
    let Ok(meta) = fs::symlink_metadata(members_path) else {
        return false;
    };
    if meta.file_type().is_symlink() || !meta.is_file() {
        return false;
    }
    let Ok(contents) = fs::read_to_string(members_path) else {
        return false;
    };
    contents
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .any(|member| member == username)
}

fn can_access_visibility(
    scope: &str,
    owner: &str,
    owner_dir: &Path,
    visibility: &str,
    creds: &UserCredentials,
) -> bool {
    if visibility != VISIBILITY_PRIVATE {
        return true;
    }
    match (scope, creds.username.as_deref()) {
        (SCOPE_USERS, Some(user)) => user == owner,
        (SCOPE_TEAMS, Some(user)) => {
            creds.team_names.iter().any(|t| t == owner)
                || is_user_in_team_members_file(&owner_dir.join("members"), user)
        }
        _ => false,
    }
}

fn matches_repository_query(
    owner: &str,
    repo_name: &str,
    canonical_path: &str,
    query_lower: &str,
) -> bool {
    if query_lower.is_empty() {
        return true;
    }
    let owner_repo = format!("{owner}/{repo_name}").to_ascii_lowercase();
    let name_lower = repo_name.to_ascii_lowercase();
    let path_lower = canonical_path.to_ascii_lowercase();
    name_lower.contains(query_lower)
        || owner_repo.contains(query_lower)
        || path_lower.contains(query_lower)
}

struct DiscoveryContext<'a> {
    normalized_host: &'a str,
    auth_user: Option<&'a str>,
    filter_query: &'a str,
}

fn scan_visibility_dir(
    vis_dir: &Path,
    scope: &str,
    owner: &str,
    visibility: &str,
    ctx: &DiscoveryContext<'_>,
    discovered: &mut Vec<DiscoveredRepository>,
) {
    if !is_non_symlink_dir(vis_dir) {
        return;
    }
    let Ok(repo_entries) = fs::read_dir(vis_dir) else {
        // PermissionDenied or unreadable directory is silently skipped
        return;
    };

    for repo_entry in repo_entries.flatten() {
        if !is_non_symlink_dir_entry(&repo_entry) {
            continue;
        }
        let repo_os = repo_entry.file_name();
        let Some(dir_name) = repo_os.to_str() else {
            continue;
        };
        let Some(repo_name) = dir_name.strip_suffix(".git") else {
            continue;
        };
        if !is_valid_identifier(repo_name) {
            continue;
        }
        // Ensure the bare repository directory itself is readable by the worker
        if fs::read_dir(repo_entry.path()).is_err() {
            continue;
        }

        let canonical_path = format_canonical_path(scope, owner, visibility, repo_name);
        if !matches_repository_query(owner, repo_name, &canonical_path, ctx.filter_query) {
            continue;
        }

        let ssh_url = format_ssh_url(ctx.normalized_host, scope, owner, visibility, repo_name);
        let clone_command = format_clone_command(
            ctx.normalized_host,
            ctx.auth_user,
            scope,
            owner,
            visibility,
            repo_name,
        );

        discovered.push(DiscoveredRepository {
            scope: scope.to_owned(),
            owner: owner.to_owned(),
            visibility: visibility.to_owned(),
            name: repo_name.to_owned(),
            canonical_path,
            ssh_url,
            clone_command,
        });
    }
}

/// Scans `<root_dir>/users` and `<root_dir>/teams` for bare `.git` repositories visible
/// to `creds`, applying optional `filter` constraints and sorting deterministically by
/// `(scope, owner, visibility, name)`.
#[must_use]
pub fn discover_repositories(
    root_dir: &Path,
    ssh_host: &str,
    creds: &UserCredentials,
    filter: &RepositoryFilter<'_>,
) -> Vec<DiscoveredRepository> {
    let filter_scope = filter.scope.trim();
    let filter_owner = filter.owner.trim();
    let filter_vis = filter.visibility.trim();
    let filter_query = filter.query.trim().to_ascii_lowercase();

    if !filter_scope.is_empty() && !is_valid_scope(filter_scope) {
        return Vec::new();
    }
    if !filter_owner.is_empty() && !is_valid_identifier(filter_owner) {
        return Vec::new();
    }
    if !filter_vis.is_empty() && !is_valid_visibility(filter_vis) {
        return Vec::new();
    }

    let ctx = DiscoveryContext {
        normalized_host: normalize_ssh_host(ssh_host),
        auth_user: creds.username.as_deref(),
        filter_query: &filter_query,
    };
    let mut discovered = Vec::new();

    for scope in [SCOPE_TEAMS, SCOPE_USERS] {
        if !filter_scope.is_empty() && filter_scope != scope {
            continue;
        }

        let scope_dir = root_dir.join(scope);
        if !is_non_symlink_dir(&scope_dir) {
            continue;
        }
        let Ok(owner_entries) = fs::read_dir(&scope_dir) else {
            continue;
        };

        for owner_entry in owner_entries.flatten() {
            if !is_non_symlink_dir_entry(&owner_entry) {
                continue;
            }
            let owner_os = owner_entry.file_name();
            let Some(owner) = owner_os.to_str() else {
                continue;
            };
            if !is_valid_identifier(owner) || (!filter_owner.is_empty() && filter_owner != owner) {
                continue;
            }

            let owner_dir = owner_entry.path();
            for visibility in [VISIBILITY_PRIVATE, VISIBILITY_PUBLIC] {
                if !filter_vis.is_empty() && filter_vis != visibility {
                    continue;
                }
                if !can_access_visibility(scope, owner, &owner_dir, visibility, creds) {
                    continue;
                }
                scan_visibility_dir(
                    &owner_dir.join(visibility),
                    scope,
                    owner,
                    visibility,
                    &ctx,
                    &mut discovered,
                );
            }
        }
    }

    discovered.sort_by(|a, b| {
        (&a.scope, &a.owner, &a.visibility, &a.name).cmp(&(
            &b.scope,
            &b.owner,
            &b.visibility,
            &b.name,
        ))
    });
    discovered
}

fn current_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn encode_worker_error(code: GrpcCode, message: &str) -> Vec<u8> {
    let bounded = truncate_utf8_str(message, 512);
    let mut buf = vec![0u8; 1024];
    let mut builder = WorkerResponseBuilder::new(&mut buf);
    builder
        .write_error_message(&bounded)
        .write_status_code(code as u32);
    builder.finish().map(<[u8]>::to_vec).unwrap_or_default()
}

fn encode_worker_ok(
    buf_size: usize,
    write_payload: impl FnOnce(&mut WorkerResponseBuilder<'_>) -> bool,
) -> Vec<u8> {
    let mut buf = vec![0u8; buf_size];
    let mut builder = WorkerResponseBuilder::new(&mut buf);
    let ok = write_payload(&mut builder);
    builder.write_status_code(GrpcCode::Ok as u32);
    if !ok {
        return encode_worker_error(GrpcCode::ResourceExhausted, "worker buffer exhausted");
    }
    match builder.finish() {
        Ok(bytes) => bytes.to_vec(),
        Err(_) => encode_worker_error(GrpcCode::ResourceExhausted, "worker buffer exhausted"),
    }
}

/// Executes a serialized `WorkerRequest` inside the worker context and returns
/// the serialized `WorkerResponse` protobuf payload.
#[must_use]
pub fn execute_worker_request_bytes(req_bytes: &[u8]) -> Vec<u8> {
    let Ok(req_view) = WorkerRequestView::from_bytes(req_bytes) else {
        return encode_worker_error(GrpcCode::InvalidArgument, "malformed WorkerRequest payload");
    };

    let token = req_view.token().unwrap_or("").trim();
    let preauth = req_view.preauthenticated_user().unwrap_or("").trim();
    let root_dir_str = req_view.root_dir().unwrap_or("/");
    let root_dir = Path::new(if root_dir_str.is_empty() {
        "/"
    } else {
        root_dir_str
    });
    let ssh_host = normalize_ssh_host(req_view.ssh_host().unwrap_or("localhost"));
    let max_ttl = req_view.max_token_ttl_secs().unwrap_or(2_592_000);
    let now_secs = match req_view.now_unix_secs().unwrap_or(0) {
        0 => current_unix_secs(),
        explicit => explicit,
    };

    let creds = if !token.is_empty() {
        let username = match verify_bearer_token(root_dir, token, now_secs, max_ttl) {
            Ok(u) => u,
            Err(err) => return encode_worker_error(GrpcCode::Unauthenticated, &err.to_string()),
        };
        match resolve_user_credentials(root_dir, None, Some(&username), 65_534) {
            Ok(c) => c,
            Err(err) => return encode_worker_error(GrpcCode::Unauthenticated, &err.to_string()),
        }
    } else if !preauth.is_empty() {
        match resolve_or_fallback_dev_credentials(root_dir, None, preauth, 65_534) {
            Ok(c) => c,
            Err(err) => return encode_worker_error(GrpcCode::Unauthenticated, &err.to_string()),
        }
    } else {
        UserCredentials {
            username: None,
            uid: 65_534,
            gid: 65_534,
            supplementary_gids: Vec::new(),
            team_names: Vec::new(),
        }
    };

    match req_view.command() {
        Ok(Some(worker_request::Command::GetAuthStatus(_))) => {
            encode_worker_ok(2048, |builder| {
                builder.write_auth_status(|auth| {
                    auth.write_ssh_host(ssh_host);
                    if let Some(ref user) = creds.username {
                        auth.write_username(user).write_authenticated(true);
                    } else {
                        auth.write_username("").write_authenticated(false);
                    }
                });
                true
            })
        }
        Ok(Some(worker_request::Command::ListRepositories(lr))) => {
            let filter = RepositoryFilter {
                scope: lr.scope().unwrap_or(""),
                owner: lr.owner().unwrap_or(""),
                visibility: lr.visibility().unwrap_or(""),
                query: lr.query().unwrap_or(""),
            };
            let repos = discover_repositories(root_dir, ssh_host, &creds, &filter);
            encode_worker_ok(65_536, |builder| {
                let mut ok = true;
                builder.write_list_repositories(|list_resp| {
                    list_resp
                        .write_ssh_host(ssh_host)
                        .write_authenticated_user(creds.username.as_deref().unwrap_or(""));
                    for repo in repos.iter().rev() {
                        list_resp.write_repositories(|r| repo.encode_into(r));
                        if list_resp.check().is_err() {
                            ok = false;
                            break;
                        }
                    }
                });
                ok
            })
        }
        Ok(Some(worker_request::Command::GetRepository(gr))) => {
            let inspection = match inspect_repository(
                root_dir,
                ssh_host,
                &creds,
                gr.scope().unwrap_or(""),
                gr.owner().unwrap_or(""),
                gr.visibility().unwrap_or(""),
                gr.name().unwrap_or(""),
                gr.revision().unwrap_or(""),
            ) {
                Ok(v) => v,
                Err((code, msg)) => return encode_worker_error(code, msg),
            };
            encode_worker_ok(512 * 1024, |builder| {
                let mut ok = true;
                builder.write_get_repository(|resp| {
                    ok = inspection.encode_into(resp);
                });
                ok
            })
        }
        Ok(Some(worker_request::Command::GetTree(gt))) => {
            let inspection = match inspect_tree(
                root_dir,
                ssh_host,
                &creds,
                gt.scope().unwrap_or(""),
                gt.owner().unwrap_or(""),
                gt.visibility().unwrap_or(""),
                gt.name().unwrap_or(""),
                gt.revision().unwrap_or(""),
                gt.path().unwrap_or(""),
            ) {
                Ok(v) => v,
                Err((code, msg)) => return encode_worker_error(code, msg),
            };
            encode_worker_ok(512 * 1024, |builder| {
                let mut ok = true;
                builder.write_get_tree(|resp| {
                    ok = inspection.encode_into(resp);
                });
                ok
            })
        }
        Ok(Some(worker_request::Command::GetBlob(gb))) => {
            let inspection = match inspect_blob(
                root_dir,
                ssh_host,
                &creds,
                gb.scope().unwrap_or(""),
                gb.owner().unwrap_or(""),
                gb.visibility().unwrap_or(""),
                gb.name().unwrap_or(""),
                gb.revision().unwrap_or(""),
                gb.path().unwrap_or(""),
            ) {
                Ok(v) => v,
                Err((code, msg)) => return encode_worker_error(code, msg),
            };
            encode_worker_ok(512 * 1024, |builder| {
                let mut ok = true;
                builder.write_get_blob(|resp| {
                    ok = inspection.encode_into(resp);
                });
                ok
            })
        }
        Ok(Some(worker_request::Command::ListCommits(lc))) => {
            let inspection = match inspect_commits(
                root_dir,
                ssh_host,
                &creds,
                lc.scope().unwrap_or(""),
                lc.owner().unwrap_or(""),
                lc.visibility().unwrap_or(""),
                lc.name().unwrap_or(""),
                lc.revision().unwrap_or(""),
                lc.path().unwrap_or(""),
                lc.limit().unwrap_or(0),
                lc.offset().unwrap_or(0),
            ) {
                Ok(v) => v,
                Err((code, msg)) => return encode_worker_error(code, msg),
            };
            encode_worker_ok(512 * 1024, |builder| {
                let mut ok = true;
                builder.write_list_commits(|resp| {
                    ok = inspection.encode_into(resp);
                });
                ok
            })
        }
        Ok(Some(worker_request::Command::GetCommit(gc))) => {
            let inspection = match inspect_commit(
                root_dir,
                ssh_host,
                &creds,
                gc.scope().unwrap_or(""),
                gc.owner().unwrap_or(""),
                gc.visibility().unwrap_or(""),
                gc.name().unwrap_or(""),
                gc.revision().unwrap_or(""),
            ) {
                Ok(v) => v,
                Err((code, msg)) => return encode_worker_error(code, msg),
            };
            encode_worker_ok(512 * 1024, |builder| {
                let mut ok = true;
                builder.write_get_commit(|resp| {
                    ok = inspection.encode_into(resp);
                });
                ok
            })
        }
        Ok(None) => encode_worker_error(GrpcCode::InvalidArgument, "missing worker command"),
        Err(_) => encode_worker_error(GrpcCode::InvalidArgument, "invalid worker command oneof"),
    }
}

/// Entrypoint for `ro-git-server git-worker`: reads a `WorkerRequest` from `stdin`,
/// executes the request, and writes the `WorkerResponse` to `stdout`.
pub fn run_worker_stdio() -> Result<(), String> {
    let mut input = Vec::new();
    std::io::stdin()
        .read_to_end(&mut input)
        .map_err(|err| format!("failed to read WorkerRequest from stdin: {err}"))?;

    let output = execute_worker_request_bytes(&input);
    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(&output)
        .map_err(|err| format!("failed to write WorkerResponse to stdout: {err}"))?;
    stdout
        .flush()
        .map_err(|err| format!("failed to flush WorkerResponse to stdout: {err}"))?;
    Ok(())
}

/// Locates the `ro-git-server` binary for spawning `git-worker` subprocesses.
#[must_use]
pub fn find_worker_binary() -> Option<PathBuf> {
    if let Ok(explicit) = std::env::var("RO_GIT_WORKER_BIN") {
        let trimmed = explicit.trim();
        if !trimmed.is_empty() {
            let path = PathBuf::from(trimmed);
            if path.is_file() {
                return Some(path);
            }
        }
    }

    let current = std::env::current_exe().ok()?;
    if current.file_name().and_then(|n| n.to_str()) == Some("ro-git-server") {
        return Some(current);
    }

    if let Some(dir) = current.parent() {
        let sibling = dir.join("ro-git-server");
        if sibling.is_file() {
            return Some(sibling);
        }
        if let Some(parent_dir) = dir.parent() {
            let parent_bin = parent_dir.join("ro-git-server");
            if parent_bin.is_file() {
                return Some(parent_bin);
            }
        }
    }

    None
}

/// Spawns `ro-git-server git-worker` as a subprocess, dropping privileges to `creds`
/// when running as `root` (`geteuid() == 0`), sending `req_bytes` over `stdin`, and
/// returning the raw `WorkerResponse` bytes from `stdout`.
#[allow(unsafe_code)]
pub fn spawn_worker_subprocess(
    worker_bin: &Path,
    creds: &UserCredentials,
    req_bytes: &[u8],
) -> Result<Vec<u8>, String> {
    let mut cmd = Command::new(worker_bin);
    cmd.arg("git-worker")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    // SAFETY: `geteuid` has no preconditions. When running as root (`UID 0`), drop
    // supplementary groups, primary GID, and UID in the child process before exec.
    if unsafe { libc::geteuid() == 0 } {
        let gids: Vec<libc::gid_t> = creds.supplementary_gids.clone();
        cmd.uid(creds.uid).gid(creds.gid);
        unsafe {
            cmd.pre_exec(move || {
                let rc = libc::setgroups(gids.len(), gids.as_ptr());
                if rc != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }

    let mut child = cmd
        .spawn()
        .map_err(|err| format!("failed to spawn git-worker subprocess: {err}"))?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(req_bytes)
            .map_err(|err| format!("failed to write to git-worker stdin: {err}"))?;
    }

    let output = child
        .wait_with_output()
        .map_err(|err| format!("failed waiting for git-worker subprocess: {err}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "git-worker exited with status {}: {}",
            output.status,
            stderr.trim()
        ));
    }

    Ok(output.stdout)
}

/// Dispatches a serialized `WorkerRequest` to a privilege-separated `git-worker`
/// subprocess (if the `ro-git-server` binary is available) or executes it directly.
pub fn dispatch_worker_request(
    creds: &UserCredentials,
    req_bytes: &[u8],
) -> Result<Vec<u8>, GrpcStatus<'static>> {
    if let Some(worker_bin) = find_worker_binary() {
        spawn_worker_subprocess(&worker_bin, creds, req_bytes)
            .map_err(|_| GrpcStatus::internal("git-worker subprocess execution failed"))
    } else {
        Ok(execute_worker_request_bytes(req_bytes))
    }
}

fn status_from_worker_code(code: u32) -> GrpcStatus<'static> {
    match code {
        c if c == GrpcCode::InvalidArgument as u32 => {
            GrpcStatus::invalid_argument("invalid worker request")
        }
        c if c == GrpcCode::NotFound as u32 => GrpcStatus::not_found("not found"),
        c if c == GrpcCode::PermissionDenied as u32 => {
            GrpcStatus::permission_denied("permission denied")
        }
        c if c == GrpcCode::ResourceExhausted as u32 => {
            GrpcStatus::resource_exhausted("worker response buffer exhausted")
        }
        c if c == GrpcCode::Unimplemented as u32 => {
            GrpcStatus::unimplemented("unimplemented worker command")
        }
        c if c == GrpcCode::Unauthenticated as u32 => {
            GrpcStatus::unauthenticated("unauthenticated or invalid SSH signature token")
        }
        _ => GrpcStatus::internal("worker execution failed"),
    }
}

/// Baseline `GitService` handler wired to `roto-grpc`.
#[derive(Clone, Debug, Default)]
pub struct GitServiceHandler {
    pub config: ServerConfig,
}

impl GitServiceHandler {
    #[must_use]
    pub const fn new(config: ServerConfig) -> Self {
        Self { config }
    }

    #[must_use]
    pub const fn into_server(self) -> GitServiceServer<Self> {
        GitServiceServer::new(self)
    }

    fn resolve_request_auth<'a>(
        &self,
        meta: &RpcMetadata<'a>,
    ) -> Result<(Option<String>, Option<String>, UserCredentials), GrpcStatus<'static>> {
        let root_path = Path::new(&self.config.root_dir);
        let now_secs = current_unix_secs();

        if let Some(raw_auth) = meta.get("authorization") {
            let auth_str = std::str::from_utf8(raw_auth)
                .map_err(|_| GrpcStatus::unauthenticated("invalid authorization header encoding"))?
                .trim();
            if !auth_str.is_empty() {
                let username = verify_bearer_token(
                    root_path,
                    auth_str,
                    now_secs,
                    self.config.max_token_ttl_secs,
                )
                .map_err(|_| {
                    GrpcStatus::unauthenticated("invalid or expired SSH signature bearer token")
                })?;
                let creds = resolve_user_credentials(
                    root_path,
                    None,
                    Some(&username),
                    self.config.nobody_uid,
                )
                .map_err(|_| GrpcStatus::unauthenticated("unable to resolve user credentials"))?;
                return Ok((Some(auth_str.to_owned()), None, creds));
            }
        }

        for header_name in ["x-forwarded-user", "remote-user"] {
            if let Some(raw_proxy_user) = meta.get(header_name) {
                let proxy_user = std::str::from_utf8(raw_proxy_user)
                    .map_err(|_| {
                        GrpcStatus::unauthenticated("invalid proxy user header encoding")
                    })?
                    .trim();
                if !proxy_user.is_empty() {
                    let creds = resolve_or_fallback_dev_credentials(
                        root_path,
                        None,
                        proxy_user,
                        self.config.nobody_uid,
                    )
                    .map_err(|_| {
                        GrpcStatus::unauthenticated("invalid proxy user header identifier")
                    })?;
                    return Ok((None, Some(proxy_user.to_owned()), creds));
                }
            }
        }

        if let Some(ref dev_user) = self.config.dev_user {
            let creds = resolve_or_fallback_dev_credentials(
                root_path,
                None,
                dev_user,
                self.config.nobody_uid,
            )
            .map_err(|_| GrpcStatus::unauthenticated("invalid RO_GIT_DEV_USER identifier"))?;
            return Ok((None, Some(dev_user.clone()), creds));
        }

        let creds = resolve_user_credentials(root_path, None, None, self.config.nobody_uid)
            .map_err(|_| GrpcStatus::internal("failed to resolve anonymous credentials"))?;
        Ok((None, None, creds))
    }

    fn execute_worker_command<'a>(
        &self,
        meta: &RpcMetadata<'a>,
        write_command: impl FnOnce(&mut WorkerRequestBuilder<'_>),
    ) -> Result<Vec<u8>, GrpcStatus<'static>> {
        let (token, preauth, creds) = self.resolve_request_auth(meta)?;
        let now_secs = current_unix_secs();

        let mut req_buf = [0u8; 4096];
        let mut req_builder = WorkerRequestBuilder::new(&mut req_buf);
        write_command(&mut req_builder);
        req_builder
            .write_now_unix_secs(now_secs)
            .write_max_token_ttl_secs(self.config.max_token_ttl_secs)
            .write_ssh_host(&self.config.ssh_host)
            .write_root_dir(&self.config.root_dir);
        if let Some(ref dev_user) = preauth {
            req_builder.write_preauthenticated_user(dev_user);
        }
        if let Some(ref tok) = token {
            req_builder.write_token(tok);
        }
        let req_bytes = req_builder
            .finish()
            .map_err(|_| GrpcStatus::resource_exhausted("worker request buffer exhausted"))?;

        let resp_bytes = dispatch_worker_request(&creds, req_bytes)?;
        let resp_view = WorkerResponseView::from_bytes(&resp_bytes)
            .map_err(|_| GrpcStatus::internal("invalid WorkerResponse from git-worker"))?;

        let status_code = resp_view.status_code().unwrap_or(GrpcCode::Ok as u32);
        if status_code != GrpcCode::Ok as u32 {
            return Err(status_from_worker_code(status_code));
        }

        Ok(resp_bytes)
    }
}

impl GitService for GitServiceHandler {
    fn get_auth_status<'a, 'b>(
        &self,
        meta: &mut RpcMetadata<'_>,
        _req: GetAuthStatusRequestView<'a>,
        resp: &mut GetAuthStatusResponseBuilder<'b>,
    ) -> Result<(), GrpcStatus<'static>> {
        let resp_bytes = self.execute_worker_command(meta, |req_builder| {
            req_builder.write_get_auth_status(|_| {});
        })?;
        let resp_view = WorkerResponseView::from_bytes(&resp_bytes)
            .map_err(|_| GrpcStatus::internal("invalid WorkerResponse from git-worker"))?;

        match resp_view.result() {
            Ok(Some(worker_response::Result::AuthStatus(auth))) => {
                resp.write_ssh_host(auth.ssh_host().unwrap_or(&self.config.ssh_host))
                    .write_username(auth.username().unwrap_or(""))
                    .write_authenticated(auth.authenticated().unwrap_or(false));
                Ok(())
            }
            _ => Err(GrpcStatus::internal("missing AuthStatus in WorkerResponse")),
        }
    }

    fn list_repositories<'a, 'b>(
        &self,
        meta: &mut RpcMetadata<'_>,
        req: ListRepositoriesRequestView<'a>,
        resp: &mut ListRepositoriesResponseBuilder<'b>,
    ) -> Result<(), GrpcStatus<'static>> {
        let scope = req.scope().unwrap_or("");
        let owner = req.owner().unwrap_or("");
        let visibility = req.visibility().unwrap_or("");
        let query = req.query().unwrap_or("");

        let resp_bytes = self.execute_worker_command(meta, |req_builder| {
            req_builder.write_list_repositories(|lr| {
                lr.write_query(query)
                    .write_visibility(visibility)
                    .write_owner(owner)
                    .write_scope(scope);
            });
        })?;
        let resp_view = WorkerResponseView::from_bytes(&resp_bytes)
            .map_err(|_| GrpcStatus::internal("invalid WorkerResponse from git-worker"))?;

        match resp_view.result() {
            Ok(Some(worker_response::Result::ListRepositories(list_view))) => {
                resp.write_ssh_host(list_view.ssh_host().unwrap_or(&self.config.ssh_host))
                    .write_authenticated_user(list_view.authenticated_user().unwrap_or(""));

                let mut decoded_repos = Vec::new();
                for item in list_view.repositories() {
                    let v = item.map_err(|_| {
                        GrpcStatus::internal("invalid RepositoryInfo in WorkerResponse")
                    })?;
                    decoded_repos.push((
                        v.scope().unwrap_or(""),
                        v.owner().unwrap_or(""),
                        v.visibility().unwrap_or(""),
                        v.name().unwrap_or(""),
                        v.canonical_path().unwrap_or(""),
                        v.ssh_url().unwrap_or(""),
                        v.clone_command().unwrap_or(""),
                    ));
                }

                for &(s, o, vis, name, cpath, surl, ccmd) in decoded_repos.iter().rev() {
                    resp.write_repositories(|r| {
                        r.write_clone_command(ccmd)
                            .write_ssh_url(surl)
                            .write_canonical_path(cpath)
                            .write_name(name)
                            .write_visibility(vis)
                            .write_owner(o)
                            .write_scope(s);
                    });
                    resp.check()
                        .map_err(|_| GrpcStatus::resource_exhausted("response buffer exhausted"))?;
                }
                Ok(())
            }
            _ => Err(GrpcStatus::internal(
                "missing ListRepositories in WorkerResponse",
            )),
        }
    }

    fn get_repository<'a, 'b>(
        &self,
        meta: &mut RpcMetadata<'_>,
        req: GetRepositoryRequestView<'a>,
        resp: &mut GetRepositoryResponseBuilder<'b>,
    ) -> Result<(), GrpcStatus<'static>> {
        let scope = req.scope().unwrap_or("");
        let owner = req.owner().unwrap_or("");
        let visibility = req.visibility().unwrap_or("");
        let name = req.name().unwrap_or("");
        let revision = req.revision().unwrap_or("");

        let resp_bytes = self.execute_worker_command(meta, |req_builder| {
            req_builder.write_get_repository(|gr| {
                gr.write_revision(revision)
                    .write_name(name)
                    .write_visibility(visibility)
                    .write_owner(owner)
                    .write_scope(scope);
            });
        })?;
        let resp_view = WorkerResponseView::from_bytes(&resp_bytes)
            .map_err(|_| GrpcStatus::internal("invalid WorkerResponse from git-worker"))?;

        match resp_view.result() {
            Ok(Some(worker_response::Result::GetRepository(gr_view))) => {
                copy_get_repository_response(gr_view, resp)
            }
            _ => Err(GrpcStatus::internal(
                "missing GetRepository in WorkerResponse",
            )),
        }
    }

    fn get_tree<'a, 'b>(
        &self,
        meta: &mut RpcMetadata<'_>,
        req: GetTreeRequestView<'a>,
        resp: &mut GetTreeResponseBuilder<'b>,
    ) -> Result<(), GrpcStatus<'static>> {
        let scope = req.scope().unwrap_or("");
        let owner = req.owner().unwrap_or("");
        let visibility = req.visibility().unwrap_or("");
        let name = req.name().unwrap_or("");
        let revision = req.revision().unwrap_or("");
        let path = req.path().unwrap_or("");

        let resp_bytes = self.execute_worker_command(meta, |req_builder| {
            req_builder.write_get_tree(|gt| {
                gt.write_path(path)
                    .write_revision(revision)
                    .write_name(name)
                    .write_visibility(visibility)
                    .write_owner(owner)
                    .write_scope(scope);
            });
        })?;
        let resp_view = WorkerResponseView::from_bytes(&resp_bytes)
            .map_err(|_| GrpcStatus::internal("invalid WorkerResponse from git-worker"))?;

        match resp_view.result() {
            Ok(Some(worker_response::Result::GetTree(gt_view))) => {
                copy_get_tree_response(gt_view, resp)
            }
            _ => Err(GrpcStatus::internal("missing GetTree in WorkerResponse")),
        }
    }

    fn get_blob<'a, 'b>(
        &self,
        meta: &mut RpcMetadata<'_>,
        req: GetBlobRequestView<'a>,
        resp: &mut GetBlobResponseBuilder<'b>,
    ) -> Result<(), GrpcStatus<'static>> {
        let scope = req.scope().unwrap_or("");
        let owner = req.owner().unwrap_or("");
        let visibility = req.visibility().unwrap_or("");
        let name = req.name().unwrap_or("");
        let revision = req.revision().unwrap_or("");
        let path = req.path().unwrap_or("");

        let resp_bytes = self.execute_worker_command(meta, |req_builder| {
            req_builder.write_get_blob(|gb| {
                gb.write_path(path)
                    .write_revision(revision)
                    .write_name(name)
                    .write_visibility(visibility)
                    .write_owner(owner)
                    .write_scope(scope);
            });
        })?;
        let resp_view = WorkerResponseView::from_bytes(&resp_bytes)
            .map_err(|_| GrpcStatus::internal("invalid WorkerResponse from git-worker"))?;

        match resp_view.result() {
            Ok(Some(worker_response::Result::GetBlob(gb_view))) => {
                copy_get_blob_response(gb_view, resp)
            }
            _ => Err(GrpcStatus::internal("missing GetBlob in WorkerResponse")),
        }
    }

    fn list_commits<'a, 'b>(
        &self,
        meta: &mut RpcMetadata<'_>,
        req: ListCommitsRequestView<'a>,
        resp: &mut ListCommitsResponseBuilder<'b>,
    ) -> Result<(), GrpcStatus<'static>> {
        let scope = req.scope().unwrap_or("");
        let owner = req.owner().unwrap_or("");
        let visibility = req.visibility().unwrap_or("");
        let name = req.name().unwrap_or("");
        let revision = req.revision().unwrap_or("");
        let path = req.path().unwrap_or("");
        let limit = req.limit().unwrap_or(0);
        let offset = req.offset().unwrap_or(0);

        let resp_bytes = self.execute_worker_command(meta, |req_builder| {
            req_builder.write_list_commits(|lc| {
                lc.write_offset(offset)
                    .write_limit(limit)
                    .write_path(path)
                    .write_revision(revision)
                    .write_name(name)
                    .write_visibility(visibility)
                    .write_owner(owner)
                    .write_scope(scope);
            });
        })?;
        let resp_view = WorkerResponseView::from_bytes(&resp_bytes)
            .map_err(|_| GrpcStatus::internal("invalid WorkerResponse from git-worker"))?;

        match resp_view.result() {
            Ok(Some(worker_response::Result::ListCommits(lc_view))) => {
                copy_list_commits_response(lc_view, resp)
            }
            _ => Err(GrpcStatus::internal(
                "missing ListCommits in WorkerResponse",
            )),
        }
    }

    fn get_commit<'a, 'b>(
        &self,
        meta: &mut RpcMetadata<'_>,
        req: GetCommitRequestView<'a>,
        resp: &mut GetCommitResponseBuilder<'b>,
    ) -> Result<(), GrpcStatus<'static>> {
        let scope = req.scope().unwrap_or("");
        let owner = req.owner().unwrap_or("");
        let visibility = req.visibility().unwrap_or("");
        let name = req.name().unwrap_or("");
        let revision = req.revision().unwrap_or("");

        let resp_bytes = self.execute_worker_command(meta, |req_builder| {
            req_builder.write_get_commit(|gc| {
                gc.write_revision(revision)
                    .write_name(name)
                    .write_visibility(visibility)
                    .write_owner(owner)
                    .write_scope(scope);
            });
        })?;
        let resp_view = WorkerResponseView::from_bytes(&resp_bytes)
            .map_err(|_| GrpcStatus::internal("invalid WorkerResponse from git-worker"))?;

        match resp_view.result() {
            Ok(Some(worker_response::Result::GetCommit(gc_view))) => {
                copy_get_commit_response(gc_view, resp)
            }
            _ => Err(GrpcStatus::internal("missing GetCommit in WorkerResponse")),
        }
    }
}

/// Static asset HTTP response returned by [`serve_static_asset`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StaticAssetResponse {
    pub status_code: u16,
    pub content_type: &'static str,
    pub body: Vec<u8>,
}

impl StaticAssetResponse {
    #[must_use]
    pub fn not_found() -> Self {
        Self {
            status_code: 404,
            content_type: "text/plain; charset=utf-8",
            body: b"not found".to_vec(),
        }
    }

    #[must_use]
    pub fn forbidden() -> Self {
        Self {
            status_code: 403,
            content_type: "text/plain; charset=utf-8",
            body: b"forbidden".to_vec(),
        }
    }
}

/// Returns the HTTP `Content-Type` header value for a static asset path based on its extension.
#[must_use]
pub fn content_type_for_path(path: &Path) -> &'static str {
    let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
        return "application/octet-stream";
    };
    if ext.eq_ignore_ascii_case("html") || ext.eq_ignore_ascii_case("htm") {
        "text/html; charset=utf-8"
    } else if ext.eq_ignore_ascii_case("wasm") {
        "application/wasm"
    } else if ext.eq_ignore_ascii_case("js") || ext.eq_ignore_ascii_case("mjs") {
        "application/javascript; charset=utf-8"
    } else if ext.eq_ignore_ascii_case("css") {
        "text/css; charset=utf-8"
    } else if ext.eq_ignore_ascii_case("svg") {
        "image/svg+xml"
    } else if ext.eq_ignore_ascii_case("json") {
        "application/json; charset=utf-8"
    } else if ext.eq_ignore_ascii_case("png") {
        "image/png"
    } else if ext.eq_ignore_ascii_case("ico") {
        "image/x-icon"
    } else if ext.eq_ignore_ascii_case("txt") {
        "text/plain; charset=utf-8"
    } else {
        "application/octet-stream"
    }
}

fn is_safe_asset_path(path: &str) -> bool {
    !path.contains('\\')
        && !path.contains('\0')
        && !path.split('/').any(|seg| seg == ".." || seg == ".")
}

fn read_regular_asset(
    path: &Path,
    content_type: &'static str,
) -> Result<Option<StaticAssetResponse>, StaticAssetResponse> {
    let Ok(meta) = fs::symlink_metadata(path) else {
        return Ok(None);
    };
    if meta.file_type().is_symlink() {
        return Err(StaticAssetResponse::forbidden());
    }
    if !meta.is_file() {
        return Ok(None);
    }
    let body = fs::read(path).map_err(|_| StaticAssetResponse::not_found())?;
    Ok(Some(StaticAssetResponse {
        status_code: 200,
        content_type,
        body,
    }))
}

fn resolve_candidate_asset(
    static_dir: &Path,
    decoded_path: &str,
) -> Result<Option<StaticAssetResponse>, StaticAssetResponse> {
    let mut candidate = static_dir.to_path_buf();
    let mut has_segments = false;
    for seg in decoded_path.split('/').filter(|s| !s.is_empty()) {
        has_segments = true;
        candidate.push(seg);
        match fs::symlink_metadata(&candidate) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(StaticAssetResponse::forbidden());
            }
            Ok(_) => {}
            Err(_) => return Ok(None),
        }
    }
    if !has_segments {
        return Ok(None);
    }
    read_regular_asset(&candidate, content_type_for_path(&candidate))
}

/// Resolves and reads a static asset from `static_dir` for `request_path`, rejecting
/// path traversal (`..`), backslashes, NUL bytes, and symlinks, and falling back to
/// `<static_dir>/index.html` for unknown non-API SPA routes.
#[must_use]
pub fn serve_static_asset(static_dir: &Path, request_path: &str) -> StaticAssetResponse {
    let raw_path = request_path.split('?').next().unwrap_or(request_path);
    if raw_path == "/api" || raw_path.starts_with("/api/") {
        return StaticAssetResponse::not_found();
    }
    if !is_safe_asset_path(raw_path) {
        return StaticAssetResponse::forbidden();
    }

    let mut decode_buf = vec![0u8; raw_path.len().max(1)];
    let Ok(decoded_path) = percent_decode_str(raw_path, &mut decode_buf) else {
        return StaticAssetResponse::forbidden();
    };
    if !is_safe_asset_path(decoded_path) {
        return StaticAssetResponse::forbidden();
    }

    match fs::symlink_metadata(static_dir) {
        Ok(meta) if meta.file_type().is_symlink() => return StaticAssetResponse::forbidden(),
        Ok(meta) if meta.is_dir() => {}
        _ => return StaticAssetResponse::not_found(),
    }

    match resolve_candidate_asset(static_dir, decoded_path) {
        Ok(Some(resp)) => return resp,
        Err(err_resp) => return err_resp,
        Ok(None) => {}
    }

    let index_path = static_dir.join("index.html");
    match read_regular_asset(&index_path, "text/html; charset=utf-8") {
        Ok(Some(resp)) => resp,
        Ok(None) => StaticAssetResponse::not_found(),
        Err(err_resp) => err_resp,
    }
}

/// `roto-grpc` service adapter serving static assets and SPA `index.html` fallback
/// when registered alongside `GitServiceServer` in a [`GrpcServer`].
#[derive(Clone, Debug)]
pub struct StaticAssetService {
    pub static_dir: PathBuf,
}

impl StaticAssetService {
    #[must_use]
    pub fn new(static_dir: impl Into<PathBuf>) -> Self {
        Self {
            static_dir: static_dir.into(),
        }
    }
}

impl GrpcService for StaticAssetService {
    const SERVICE_NAME: &'static str = "ro_git.v1.StaticAssets";

    fn call_unary(
        &self,
        _meta: &mut RpcMetadata<'_>,
        _method_name: &str,
        _req_payload: &[u8],
        _writer: &mut BackwardWriter<'_>,
    ) -> Result<(), GrpcStatus<'static>> {
        Err(GrpcStatus::unimplemented("unimplemented gRPC method"))
    }

    fn call_http<'a, 's, 'b>(
        &self,
        req: &HttpRequest<'a>,
        scratch: &'s mut [u8],
        writer: &mut BackwardWriter<'b>,
    ) -> Option<Result<HttpResponse<'b>, GrpcStatus<'static>>> {
        <Self as HttpService>::call_http(self, req, scratch, writer)
    }
}

impl HttpService for StaticAssetService {
    fn call_http<'a, 's, 'b>(
        &self,
        req: &HttpRequest<'a>,
        _scratch: &'s mut [u8],
        writer: &mut BackwardWriter<'b>,
    ) -> Option<Result<HttpResponse<'b>, GrpcStatus<'static>>> {
        if req.path == "/api" || req.path.starts_with("/api/") {
            return None;
        }
        if req.method != HttpMethod::Get {
            return Some(Err(GrpcStatus::invalid_argument("method not allowed")));
        }

        let asset = serve_static_asset(&self.static_dir, req.path);
        match asset.status_code {
            200 => {
                if writer.write_bytes(&asset.body).is_err() || writer.check().is_err() {
                    return Some(Err(GrpcStatus::resource_exhausted(
                        "static asset response buffer exhausted",
                    )));
                }
                let mut resp = match finish_writer_response(writer, None) {
                    Ok(r) => r,
                    Err(e) => return Some(Err(e)),
                };
                resp.content_type = asset.content_type;
                Some(Ok(resp))
            }
            403 => Some(Err(GrpcStatus::permission_denied("forbidden"))),
            _ => Some(Err(GrpcStatus::not_found("not found"))),
        }
    }
}

const fn http_status_from_grpc_code(code: GrpcCode) -> u16 {
    match code {
        GrpcCode::Ok => 200,
        GrpcCode::Cancelled => 499,
        GrpcCode::InvalidArgument | GrpcCode::FailedPrecondition | GrpcCode::OutOfRange => 400,
        GrpcCode::DeadlineExceeded => 504,
        GrpcCode::NotFound => 404,
        GrpcCode::AlreadyExists | GrpcCode::Aborted => 409,
        GrpcCode::PermissionDenied => 403,
        GrpcCode::ResourceExhausted => 429,
        GrpcCode::Unimplemented => 501,
        GrpcCode::Unavailable => 503,
        GrpcCode::Unauthenticated => 401,
        _ => 500,
    }
}

fn push_json_escaped(out: &mut String, s: &str) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = fmt::Write::write_fmt(out, format_args!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn encode_auth_status_json(view: GetAuthStatusResponseView<'_>) -> Vec<u8> {
    let authenticated = view.authenticated().unwrap_or(false);
    let username = view.username().unwrap_or("");
    let ssh_host = view.ssh_host().unwrap_or("");

    let mut json = String::with_capacity(128);
    json.push_str("{\"authenticated\":");
    json.push_str(if authenticated { "true" } else { "false" });
    json.push_str(",\"username\":");
    push_json_escaped(&mut json, username);
    json.push_str(",\"ssh_host\":");
    push_json_escaped(&mut json, ssh_host);
    json.push('}');
    json.into_bytes()
}

fn encode_list_repositories_json(view: ListRepositoriesResponseView<'_>) -> Vec<u8> {
    let auth_user = view.authenticated_user().unwrap_or("");
    let ssh_host = view.ssh_host().unwrap_or("");

    let mut json = String::with_capacity(512);
    json.push_str("{\"repositories\":[");
    let mut first = true;
    for item in view.repositories().flatten() {
        if !first {
            json.push(',');
        }
        first = false;
        push_repository_info_json(&mut json, item);
    }
    json.push_str("],\"authenticated_user\":");
    push_json_escaped(&mut json, auth_user);
    json.push_str(",\"ssh_host\":");
    push_json_escaped(&mut json, ssh_host);
    json.push('}');
    json.into_bytes()
}

#[derive(Clone, Debug, Default)]
struct ParsedH1Request {
    method: String,
    path: String,
    query: String,
    authorization: Option<String>,
    x_forwarded_user: Option<String>,
    remote_user: Option<String>,
    accept: Option<String>,
    connection_close: bool,
}

struct H1Response {
    status_code: u16,
    content_type: &'static str,
    body: Vec<u8>,
    omit_body: bool,
}

impl H1Response {
    fn plain_error(status_code: u16, message: &str, omit_body: bool) -> Self {
        Self {
            status_code,
            content_type: "text/plain; charset=utf-8",
            body: message.as_bytes().to_vec(),
            omit_body,
        }
    }

    fn from_grpc_status(status: GrpcStatus<'_>, omit_body: bool) -> Self {
        Self::plain_error(
            http_status_from_grpc_code(status.code),
            status.message,
            omit_body,
        )
    }
}

fn parse_h1_headers(header_bytes: &[u8]) -> Option<(ParsedH1Request, usize)> {
    let header_str = std::str::from_utf8(header_bytes).ok()?;
    let mut lines = header_str.split("\r\n");
    let req_line = lines.next()?;
    let mut parts = req_line.split_whitespace();
    let method = parts.next()?.to_owned();
    let target = parts.next()?;
    let _version = parts.next()?;

    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p.to_owned(), q.to_owned()),
        None => (target.to_owned(), String::new()),
    };

    let mut parsed = ParsedH1Request {
        method,
        path,
        query,
        ..ParsedH1Request::default()
    };
    let mut content_length = 0usize;

    for line in lines {
        if line.is_empty() {
            break;
        }
        let Some((name, val)) = line.split_once(':') else {
            continue;
        };
        let name_trimmed = name.trim();
        let val_trimmed = val.trim();
        if name_trimmed.eq_ignore_ascii_case("authorization") {
            parsed.authorization = Some(val_trimmed.to_owned());
        } else if name_trimmed.eq_ignore_ascii_case("x-forwarded-user") {
            parsed.x_forwarded_user = Some(val_trimmed.to_owned());
        } else if name_trimmed.eq_ignore_ascii_case("remote-user") {
            parsed.remote_user = Some(val_trimmed.to_owned());
        } else if name_trimmed.eq_ignore_ascii_case("accept") {
            parsed.accept = Some(val_trimmed.to_owned());
        } else if name_trimmed.eq_ignore_ascii_case("content-length") {
            content_length = val_trimmed.parse::<usize>().ok()?;
        } else if name_trimmed.eq_ignore_ascii_case("connection")
            && val_trimmed.eq_ignore_ascii_case("close")
        {
            parsed.connection_close = true;
        }
    }

    Some((parsed, content_length))
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

fn build_rpc_context(req: &ParsedH1Request) -> RpcContext<DynamicMetadata> {
    let mut ctx = RpcContext::<DynamicMetadata>::new();
    if let Some(ref auth) = req.authorization {
        let _ = ctx.request.insert("authorization", auth);
    }
    if let Some(ref xfu) = req.x_forwarded_user {
        let _ = ctx.request.insert("x-forwarded-user", xfu);
    }
    if let Some(ref ru) = req.remote_user {
        let _ = ctx.request.insert("remote-user", ru);
    }
    ctx
}

fn wants_json(accept: Option<&str>) -> bool {
    accept
        .map(|a| {
            a.split(',').any(|part| {
                let media = part.split(';').next().unwrap_or("").trim();
                media.eq_ignore_ascii_case("application/json")
            })
        })
        .unwrap_or(false)
}

fn finish_h1_proto_or_json<'a, V, E1, E2>(
    proto_res: Result<&'a [u8], E1>,
    accept: Option<&str>,
    omit_body: bool,
    from_bytes: impl FnOnce(&'a [u8]) -> Result<V, E2>,
    encode_json: impl FnOnce(V) -> Vec<u8>,
) -> H1Response {
    let Ok(proto_bytes) = proto_res else {
        return H1Response::plain_error(500, "response buffer exhausted", omit_body);
    };
    if wants_json(accept) {
        if let Ok(view) = from_bytes(proto_bytes) {
            return H1Response {
                status_code: 200,
                content_type: "application/json; charset=utf-8",
                body: encode_json(view),
                omit_body,
            };
        }
    }
    H1Response {
        status_code: 200,
        content_type: "application/x-protobuf",
        body: proto_bytes.to_vec(),
        omit_body,
    }
}

fn handle_h1_auth_status(
    handler: &GitServiceHandler,
    req: &ParsedH1Request,
    omit_body: bool,
) -> H1Response {
    let Ok(req_view) = GetAuthStatusRequestView::from_bytes(&[]) else {
        return H1Response::plain_error(500, "internal error", omit_body);
    };
    let mut ctx = build_rpc_context(req);
    let mut meta = ctx.metadata();
    let mut buf = vec![0u8; 4096];
    let mut builder = GetAuthStatusResponseBuilder::new(&mut buf);
    if let Err(status) = handler.get_auth_status(&mut meta, req_view, &mut builder) {
        return H1Response::from_grpc_status(status, omit_body);
    }
    finish_h1_proto_or_json(
        builder.finish(),
        req.accept.as_deref(),
        omit_body,
        GetAuthStatusResponseView::from_bytes,
        encode_auth_status_json,
    )
}

fn handle_h1_list_repositories(
    handler: &GitServiceHandler,
    req: &ParsedH1Request,
    omit_body: bool,
) -> H1Response {
    let mut raw_scope = "";
    let mut raw_owner = "";
    let mut raw_vis = "";
    let mut raw_query = "";

    for (k, v) in QueryIter::new(&req.query) {
        match k {
            "scope" => raw_scope = v,
            "owner" => raw_owner = v,
            "visibility" => raw_vis = v,
            "query" => raw_query = v,
            _ => {}
        }
    }

    let mut scope_buf = [0u8; 128];
    let mut owner_buf = [0u8; 128];
    let mut vis_buf = [0u8; 128];
    let mut query_buf = [0u8; 512];
    let scope_val = percent_decode_str(raw_scope, &mut scope_buf).unwrap_or("");
    let owner_val = percent_decode_str(raw_owner, &mut owner_buf).unwrap_or("");
    let vis_val = percent_decode_str(raw_vis, &mut vis_buf).unwrap_or("");
    let query_val = percent_decode_str(raw_query, &mut query_buf).unwrap_or("");

    let mut req_buf = [0u8; 1024];
    let mut req_builder = ListRepositoriesRequestBuilder::new(&mut req_buf);
    req_builder
        .write_query(query_val)
        .write_visibility(vis_val)
        .write_owner(owner_val)
        .write_scope(scope_val);
    let Ok(req_bytes) = req_builder.finish() else {
        return H1Response::plain_error(400, "query parameters too large", omit_body);
    };
    let Ok(req_view) = ListRepositoriesRequestView::from_bytes(req_bytes) else {
        return H1Response::plain_error(400, "invalid request", omit_body);
    };

    let mut ctx = build_rpc_context(req);
    let mut meta = ctx.metadata();
    let mut resp_buf = vec![0u8; 65_536];
    let mut resp_builder = ListRepositoriesResponseBuilder::new(&mut resp_buf);
    if let Err(status) = handler.list_repositories(&mut meta, req_view, &mut resp_builder) {
        return H1Response::from_grpc_status(status, omit_body);
    }
    finish_h1_proto_or_json(
        resp_builder.finish(),
        req.accept.as_deref(),
        omit_body,
        ListRepositoriesResponseView::from_bytes,
        encode_list_repositories_json,
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RepoSubRoute<'a> {
    GetRepository {
        scope: &'a str,
        owner: &'a str,
        visibility: &'a str,
        name: &'a str,
    },
    GetTree {
        scope: &'a str,
        owner: &'a str,
        visibility: &'a str,
        name: &'a str,
    },
    GetBlob {
        scope: &'a str,
        owner: &'a str,
        visibility: &'a str,
        name: &'a str,
    },
    ListCommits {
        scope: &'a str,
        owner: &'a str,
        visibility: &'a str,
        name: &'a str,
    },
    GetCommit {
        scope: &'a str,
        owner: &'a str,
        visibility: &'a str,
        name: &'a str,
    },
}

impl<'a> RepoSubRoute<'a> {
    const fn params(self) -> (&'a str, &'a str, &'a str, &'a str) {
        match self {
            Self::GetRepository {
                scope,
                owner,
                visibility,
                name,
            }
            | Self::GetTree {
                scope,
                owner,
                visibility,
                name,
            }
            | Self::GetBlob {
                scope,
                owner,
                visibility,
                name,
            }
            | Self::ListCommits {
                scope,
                owner,
                visibility,
                name,
            }
            | Self::GetCommit {
                scope,
                owner,
                visibility,
                name,
            } => (scope, owner, visibility, name),
        }
    }
}

fn match_repo_sub_route(path: &str) -> Option<RepoSubRoute<'_>> {
    let rest = path.strip_prefix("/api/v1/repositories/")?;
    let mut parts = rest.split('/');
    let scope = parts.next().filter(|s| !s.is_empty())?;
    let owner = parts.next().filter(|s| !s.is_empty())?;
    let visibility = parts.next().filter(|s| !s.is_empty())?;
    let name = parts.next().filter(|s| !s.is_empty())?;
    match parts.next() {
        None => Some(RepoSubRoute::GetRepository {
            scope,
            owner,
            visibility,
            name,
        }),
        Some(action) if parts.next().is_none() => match action {
            "tree" => Some(RepoSubRoute::GetTree {
                scope,
                owner,
                visibility,
                name,
            }),
            "blob" => Some(RepoSubRoute::GetBlob {
                scope,
                owner,
                visibility,
                name,
            }),
            "commits" => Some(RepoSubRoute::ListCommits {
                scope,
                owner,
                visibility,
                name,
            }),
            "commit" => Some(RepoSubRoute::GetCommit {
                scope,
                owner,
                visibility,
                name,
            }),
            _ => None,
        },
        _ => None,
    }
}

fn parse_optional_u32_query_param(raw: Option<&str>) -> Option<u32> {
    let Some(s) = raw.filter(|s| !s.is_empty()) else {
        return Some(0);
    };
    let mut buf = [0u8; 64];
    let decoded = percent_decode_str(s, &mut buf).ok()?;
    decoded.parse::<u32>().ok()
}

fn handle_h1_repo_sub_route(
    handler: &GitServiceHandler,
    req: &ParsedH1Request,
    route: RepoSubRoute<'_>,
    omit_body: bool,
) -> H1Response {
    let (raw_scope, raw_owner, raw_vis, raw_name) = route.params();
    let mut scope_buf = [0u8; 128];
    let mut owner_buf = [0u8; 128];
    let mut vis_buf = [0u8; 128];
    let mut name_buf = [0u8; 128];

    let Ok(scope) = percent_decode_str(raw_scope, &mut scope_buf) else {
        return H1Response::plain_error(400, "invalid path parameter encoding", omit_body);
    };
    let Ok(owner) = percent_decode_str(raw_owner, &mut owner_buf) else {
        return H1Response::plain_error(400, "invalid path parameter encoding", omit_body);
    };
    let Ok(visibility) = percent_decode_str(raw_vis, &mut vis_buf) else {
        return H1Response::plain_error(400, "invalid path parameter encoding", omit_body);
    };
    let Ok(name) = percent_decode_str(raw_name, &mut name_buf) else {
        return H1Response::plain_error(400, "invalid path parameter encoding", omit_body);
    };

    let mut raw_rev = "";
    let mut raw_path = "";
    let mut raw_limit: Option<&str> = None;
    let mut raw_offset: Option<&str> = None;

    for (k, v) in QueryIter::new(&req.query) {
        match k {
            "revision" => raw_rev = v,
            "path" => raw_path = v,
            "limit" => raw_limit = Some(v),
            "offset" => raw_offset = Some(v),
            _ => {}
        }
    }

    let mut rev_buf = [0u8; 256];
    let mut path_buf = [0u8; 1024];
    let Ok(revision) = percent_decode_str(raw_rev, &mut rev_buf) else {
        return H1Response::plain_error(400, "invalid revision parameter encoding", omit_body);
    };
    let Ok(path) = percent_decode_str(raw_path, &mut path_buf) else {
        return H1Response::plain_error(400, "invalid path parameter encoding", omit_body);
    };

    let Some(limit_val) = parse_optional_u32_query_param(raw_limit) else {
        return H1Response::plain_error(400, "invalid limit parameter", omit_body);
    };
    let Some(offset_val) = parse_optional_u32_query_param(raw_offset) else {
        return H1Response::plain_error(400, "invalid offset parameter", omit_body);
    };

    let mut ctx = build_rpc_context(req);
    let mut meta = ctx.metadata();
    let mut req_buf = [0u8; 2048];
    let mut resp_buf = vec![0u8; 512 * 1024];
    let accept = req.accept.as_deref();

    match route {
        RepoSubRoute::GetRepository { .. } => {
            let mut b = GetRepositoryRequestBuilder::new(&mut req_buf);
            b.write_revision(revision)
                .write_name(name)
                .write_visibility(visibility)
                .write_owner(owner)
                .write_scope(scope);
            let Ok(req_bytes) = b.finish() else {
                return H1Response::plain_error(400, "request parameters too large", omit_body);
            };
            let Ok(req_view) = GetRepositoryRequestView::from_bytes(req_bytes) else {
                return H1Response::plain_error(400, "invalid request", omit_body);
            };
            let mut resp_builder = GetRepositoryResponseBuilder::new(&mut resp_buf);
            if let Err(status) = handler.get_repository(&mut meta, req_view, &mut resp_builder) {
                return H1Response::from_grpc_status(status, omit_body);
            }
            finish_h1_proto_or_json(
                resp_builder.finish(),
                accept,
                omit_body,
                GetRepositoryResponseView::from_bytes,
                encode_get_repository_json,
            )
        }
        RepoSubRoute::GetTree { .. } => {
            let mut b = GetTreeRequestBuilder::new(&mut req_buf);
            b.write_path(path)
                .write_revision(revision)
                .write_name(name)
                .write_visibility(visibility)
                .write_owner(owner)
                .write_scope(scope);
            let Ok(req_bytes) = b.finish() else {
                return H1Response::plain_error(400, "request parameters too large", omit_body);
            };
            let Ok(req_view) = GetTreeRequestView::from_bytes(req_bytes) else {
                return H1Response::plain_error(400, "invalid request", omit_body);
            };
            let mut resp_builder = GetTreeResponseBuilder::new(&mut resp_buf);
            if let Err(status) = handler.get_tree(&mut meta, req_view, &mut resp_builder) {
                return H1Response::from_grpc_status(status, omit_body);
            }
            finish_h1_proto_or_json(
                resp_builder.finish(),
                accept,
                omit_body,
                GetTreeResponseView::from_bytes,
                encode_get_tree_json,
            )
        }
        RepoSubRoute::GetBlob { .. } => {
            let mut b = GetBlobRequestBuilder::new(&mut req_buf);
            b.write_path(path)
                .write_revision(revision)
                .write_name(name)
                .write_visibility(visibility)
                .write_owner(owner)
                .write_scope(scope);
            let Ok(req_bytes) = b.finish() else {
                return H1Response::plain_error(400, "request parameters too large", omit_body);
            };
            let Ok(req_view) = GetBlobRequestView::from_bytes(req_bytes) else {
                return H1Response::plain_error(400, "invalid request", omit_body);
            };
            let mut resp_builder = GetBlobResponseBuilder::new(&mut resp_buf);
            if let Err(status) = handler.get_blob(&mut meta, req_view, &mut resp_builder) {
                return H1Response::from_grpc_status(status, omit_body);
            }
            finish_h1_proto_or_json(
                resp_builder.finish(),
                accept,
                omit_body,
                GetBlobResponseView::from_bytes,
                encode_get_blob_json,
            )
        }
        RepoSubRoute::ListCommits { .. } => {
            let mut b = ListCommitsRequestBuilder::new(&mut req_buf);
            b.write_offset(offset_val)
                .write_limit(limit_val)
                .write_path(path)
                .write_revision(revision)
                .write_name(name)
                .write_visibility(visibility)
                .write_owner(owner)
                .write_scope(scope);
            let Ok(req_bytes) = b.finish() else {
                return H1Response::plain_error(400, "request parameters too large", omit_body);
            };
            let Ok(req_view) = ListCommitsRequestView::from_bytes(req_bytes) else {
                return H1Response::plain_error(400, "invalid request", omit_body);
            };
            let mut resp_builder = ListCommitsResponseBuilder::new(&mut resp_buf);
            if let Err(status) = handler.list_commits(&mut meta, req_view, &mut resp_builder) {
                return H1Response::from_grpc_status(status, omit_body);
            }
            finish_h1_proto_or_json(
                resp_builder.finish(),
                accept,
                omit_body,
                ListCommitsResponseView::from_bytes,
                encode_list_commits_json,
            )
        }
        RepoSubRoute::GetCommit { .. } => {
            let mut b = GetCommitRequestBuilder::new(&mut req_buf);
            b.write_revision(revision)
                .write_name(name)
                .write_visibility(visibility)
                .write_owner(owner)
                .write_scope(scope);
            let Ok(req_bytes) = b.finish() else {
                return H1Response::plain_error(400, "request parameters too large", omit_body);
            };
            let Ok(req_view) = GetCommitRequestView::from_bytes(req_bytes) else {
                return H1Response::plain_error(400, "invalid request", omit_body);
            };
            let mut resp_builder = GetCommitResponseBuilder::new(&mut resp_buf);
            if let Err(status) = handler.get_commit(&mut meta, req_view, &mut resp_builder) {
                return H1Response::from_grpc_status(status, omit_body);
            }
            finish_h1_proto_or_json(
                resp_builder.finish(),
                accept,
                omit_body,
                GetCommitResponseView::from_bytes,
                encode_get_commit_json,
            )
        }
    }
}

fn dispatch_h1_request(handler: &GitServiceHandler, req: &ParsedH1Request) -> H1Response {
    let is_head = req.method.eq_ignore_ascii_case("HEAD");
    let is_get = req.method.eq_ignore_ascii_case("GET");

    let repo_sub_route = match_repo_sub_route(&req.path);
    let is_known_api = req.path == API_AUTH_STATUS_PATH
        || req.path == API_REPOSITORIES_PATH
        || repo_sub_route.is_some();

    if (req.path == "/api" || req.path.starts_with("/api/")) && !is_known_api {
        return H1Response::plain_error(404, "not found", is_head);
    }
    if !is_get && !is_head {
        return H1Response::plain_error(405, "method not allowed", false);
    }

    if req.path == API_AUTH_STATUS_PATH {
        handle_h1_auth_status(handler, req, is_head)
    } else if req.path == API_REPOSITORIES_PATH {
        handle_h1_list_repositories(handler, req, is_head)
    } else if let Some(route) = repo_sub_route {
        handle_h1_repo_sub_route(handler, req, route, is_head)
    } else {
        let asset = serve_static_asset(Path::new(&handler.config.static_dir), &req.path);
        H1Response {
            status_code: asset.status_code,
            content_type: asset.content_type,
            body: asset.body,
            omit_body: is_head,
        }
    }
}

fn write_h1_response<W: Write>(
    stream: &mut W,
    resp: &H1Response,
    connection_close: bool,
) -> io::Result<()> {
    let status_code = resp.status_code;
    let content_type = resp.content_type;
    let reason = http_reason_phrase(status_code);
    let conn_hdr = if connection_close {
        "close"
    } else {
        "keep-alive"
    };
    let header = format!(
        "HTTP/1.1 {status_code} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: {conn_hdr}\r\n\r\n",
        resp.body.len()
    );
    stream.write_all(header.as_bytes())?;
    if !resp.omit_body {
        stream.write_all(&resp.body)?;
    }
    stream.flush()
}

struct PrefixedStream<S> {
    prefix: Vec<u8>,
    offset: usize,
    inner: S,
}

impl<S> PrefixedStream<S> {
    const fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self {
            prefix,
            offset: 0,
            inner,
        }
    }
}

impl<S: Read> Read for PrefixedStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.offset < self.prefix.len() {
            let rem = &self.prefix[self.offset..];
            let n = buf.len().min(rem.len());
            buf[..n].copy_from_slice(&rem[..n]);
            self.offset += n;
            return Ok(n);
        }
        self.inner.read(buf)
    }
}

impl<S: Write> Write for PrefixedStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

fn read_chunk_uninterrupted<R: Read>(reader: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    loop {
        match reader.read(buf) {
            Ok(n) => return Ok(n),
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        }
    }
}

fn serve_h1_connection<S: Read + Write>(mut io: S, config: ServerConfig) -> io::Result<()> {
    const MAX_HEADER_BYTES: usize = 32 * 1024;
    const MAX_BODY_BYTES: usize = 64 * 1024;

    let handler = GitServiceHandler::new(config);
    let mut buf = Vec::with_capacity(4096);
    let mut scratch = [0u8; 4096];

    loop {
        let header_end = loop {
            if let Some(end) = find_header_end(&buf) {
                break end;
            }
            if buf.len() >= MAX_HEADER_BYTES {
                let err_resp = H1Response::plain_error(400, "request headers too large", false);
                let _ = write_h1_response(&mut io, &err_resp, true);
                return Ok(());
            }
            let n = read_chunk_uninterrupted(&mut io, &mut scratch)?;
            if n == 0 {
                return Ok(());
            }
            buf.extend_from_slice(&scratch[..n]);
        };

        let Some((parsed_req, content_length)) = parse_h1_headers(&buf[..header_end]) else {
            let err_resp = H1Response::plain_error(400, "bad request", false);
            let _ = write_h1_response(&mut io, &err_resp, true);
            return Ok(());
        };

        if content_length > MAX_BODY_BYTES {
            let err_resp = H1Response::plain_error(413, "payload too large", false);
            let _ = write_h1_response(&mut io, &err_resp, true);
            return Ok(());
        }

        let total_req_len = header_end + content_length;
        while buf.len() < total_req_len {
            let n = read_chunk_uninterrupted(&mut io, &mut scratch)?;
            if n == 0 {
                return Ok(());
            }
            buf.extend_from_slice(&scratch[..n]);
        }

        buf.drain(..total_req_len);

        let resp = dispatch_h1_request(&handler, &parsed_req);
        write_h1_response(&mut io, &resp, parsed_req.connection_close)?;

        if parsed_req.connection_close {
            return Ok(());
        }
    }
}

/// Serves a single TCP connection, automatically detecting HTTP/2 (`roto-grpc` unary gRPC
/// and HTTP/2 routes) vs HTTP/1.1 (`/api/v1/...` and static asset hosting).
pub fn serve_tcp_stream(mut stream: TcpStream, config: ServerConfig) -> io::Result<()> {
    let _ = stream.set_nodelay(true);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));

    let mut prefix = Vec::with_capacity(64);
    let mut temp = [0u8; 64];
    let is_h2 = loop {
        if let Some(detected) = roto_grpc::is_h2_client_preface(&prefix) {
            break detected;
        }
        let n = read_chunk_uninterrupted(&mut stream, &mut temp)?;
        if n == 0 {
            if prefix.is_empty() {
                return Ok(());
            }
            break false;
        }
        prefix.extend_from_slice(&temp[..n]);
    };

    let io = PrefixedStream::new(prefix, stream);

    if is_h2 {
        let static_service = StaticAssetService::new(&config.static_dir);
        let git_service = GitServiceHandler::new(config).into_server();
        let routes: [&dyn Route; 2] = [&git_service, &static_service];
        let mut msg_buf = vec![0u8; 512 * 1024];
        let mut tx_buf = vec![0u8; 512 * 1024];
        let mut server =
            GrpcServer::<4, 4096, DynamicMetadata>::with_metadata_store(&routes, &mut msg_buf, &mut tx_buf);
        let _ = roto_grpc::serve_std_io(&mut server, io);
        Ok(())
    } else {
        serve_h1_connection(io, config)
    }
}

/// Handle to a running background `ro-git-server` TCP listener.
pub struct RunningServer {
    local_addr: SocketAddr,
    shutdown: Arc<AtomicBool>,
    join_handle: Option<std::thread::JoinHandle<()>>,
}

impl RunningServer {
    /// Returns the bound local socket address of the server.
    #[must_use]
    pub const fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Signals the server accept loop to stop and waits for it to exit.
    pub fn shutdown(mut self) {
        self.shutdown_inner();
    }

    fn shutdown_inner(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.local_addr);
        if let Some(handle) = self.join_handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for RunningServer {
    fn drop(&mut self) {
        self.shutdown_inner();
    }
}

/// Binds a TCP listener to `config.listen_addr` and spawns a background accept thread
/// serving both `roto-grpc` HTTP/2 and HTTP/1.1 requests.
pub fn start_server(config: ServerConfig) -> io::Result<RunningServer> {
    let listener = TcpListener::bind(&config.listen_addr)?;
    let local_addr = listener.local_addr()?;
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_flag = Arc::clone(&shutdown);

    let join_handle = std::thread::spawn(move || {
        for incoming in listener.incoming() {
            if shutdown_flag.load(Ordering::SeqCst) {
                break;
            }
            if let Ok(stream) = incoming {
                let conn_config = config.clone();
                std::thread::spawn(move || {
                    let _ = serve_tcp_stream(stream, conn_config);
                });
            }
        }
    });

    Ok(RunningServer {
        local_addr,
        shutdown,
        join_handle: Some(join_handle),
    })
}

/// Binds a TCP listener to `config.listen_addr` and serves incoming HTTP/2 and HTTP/1.1
/// connections on the current thread until the process terminates.
pub fn run_server(config: ServerConfig) -> io::Result<()> {
    let listener = TcpListener::bind(&config.listen_addr)?;
    for stream in listener.incoming().flatten() {
        let conn_config = config.clone();
        std::thread::spawn(move || {
            let _ = serve_tcp_stream(stream, conn_config);
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ro_git_proto::ro_git::v1::{GetAuthStatusResponseView, ListRepositoriesResponseView};
    use ro_git_proto::{
        encode_bearer_token, format_token_payload, API_AUTH_STATUS_PATH, API_REPOSITORIES_PATH,
    };
    use roto::runtime::BackwardWriter;
    use roto_grpc::http::{HttpMethod, HttpRequest};
    use roto_grpc::RpcContext;
    use ssh_key::{HashAlg, LineEnding, PrivateKey};
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

    struct TempRoot {
        path: PathBuf,
    }

    impl TempRoot {
        fn new(prefix: &str) -> Self {
            let seq = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
            let dir = std::env::temp_dir()
                .join(format!("ro-git-test-{prefix}-{}-{seq}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).expect("create temp root");
            Self { path: dir }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempRoot {
        fn drop(&mut self) {
            // Restore permissions before removal in case a test chmod'd 0000
            if let Ok(entries) = fs::read_dir(&self.path) {
                for entry in entries.flatten() {
                    let _ = fs::set_permissions(entry.path(), fs::Permissions::from_mode(0o755));
                }
            }
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn test_ed25519_keypair(seed_byte: u8) -> (PrivateKey, String) {
        let secret_bytes = [seed_byte; 32];
        let kp = ssh_key::private::Ed25519Keypair::from_seed(&secret_bytes);
        let priv_key = PrivateKey::from(kp);
        let pub_openssh = priv_key
            .public_key()
            .to_openssh()
            .expect("serialize openssh public key");
        (priv_key, pub_openssh)
    }

    fn sign_token_with_key(
        priv_key: &PrivateKey,
        namespace: &str,
        payload: &str,
    ) -> (String, String) {
        let sig = priv_key
            .sign(namespace, HashAlg::Sha512, payload.as_bytes())
            .expect("sign payload");
        let pem = sig.to_pem(LineEnding::LF).expect("encode sshsig pem");
        let token = encode_bearer_token(payload, &pem).expect("encode bearer token");
        (pem, token)
    }

    fn write_authorized_keys(root: &Path, username: &str, content: &str, mode: u32) -> PathBuf {
        let user_dir = root.join("users").join(username);
        fs::create_dir_all(&user_dir).expect("create user dir");
        let ak_path = user_dir.join("authorized_keys");
        fs::write(&ak_path, content).expect("write authorized_keys");
        fs::set_permissions(&ak_path, fs::Permissions::from_mode(mode))
            .expect("chmod authorized_keys");
        ak_path
    }

    #[test]
    fn default_config_matches_readme_specification() {
        let cfg = ServerConfig::default();
        assert_eq!(cfg.listen_addr, "0.0.0.0:8080");
        assert_eq!(cfg.root_dir, "/");
        assert_eq!(cfg.ssh_host, "localhost");
        assert_eq!(cfg.static_dir, "/app/dist");
        assert_eq!(cfg.max_token_ttl_secs, 2_592_000);
        assert_eq!(cfg.nobody_uid, 65_534);
        assert_eq!(cfg.dev_user, None);
    }

    #[test]
    fn from_env_and_lookup_override_and_fallback_cleanly() {
        let cfg = ServerConfig::from_lookup(|key| match key {
            "RO_GIT_LISTEN_ADDR" => Some(String::from(" 127.0.0.1:9090 ")),
            "RO_GIT_ROOT" => Some(String::from(" /srv/ro-git ")),
            "RO_GIT_SSH_HOST" => Some(String::from(" git.example.com:2222 ")),
            "RO_GIT_STATIC_DIR" => Some(String::from(" /var/www/ro-git ")),
            "RO_GIT_MAX_TOKEN_TTL_SECS" => Some(String::from(" 86400 ")),
            "RO_GIT_NOBODY_UID" => Some(String::from(" 10001 ")),
            "RO_GIT_DEV_USER" => Some(String::from(" alice ")),
            _ => None,
        });
        assert_eq!(cfg.listen_addr, "127.0.0.1:9090");
        assert_eq!(cfg.root_dir, "/srv/ro-git");
        assert_eq!(cfg.ssh_host, "git.example.com:2222");
        assert_eq!(cfg.static_dir, "/var/www/ro-git");
        assert_eq!(cfg.max_token_ttl_secs, 86_400);
        assert_eq!(cfg.nobody_uid, 10_001);
        assert_eq!(cfg.dev_user.as_deref(), Some("alice"));

        let fallback = ServerConfig::from_lookup(|key| match key {
            "RO_GIT_LISTEN_ADDR" => Some(String::from("   ")),
            "RO_GIT_MAX_TOKEN_TTL_SECS" => Some(String::from("not-a-number")),
            "RO_GIT_NOBODY_UID" => Some(String::from("-1")),
            "RO_GIT_DEV_USER" => Some(String::from("")),
            _ => None,
        });
        assert_eq!(fallback, ServerConfig::default());

        let env_cfg = ServerConfig::from_env();
        assert!(!env_cfg.listen_addr.is_empty());
        assert!(!env_cfg.ssh_host.is_empty());
    }

    #[test]
    fn git_service_handler_serves_auth_status_and_repositories_over_http() {
        let mut scratch = [0u8; 512];
        let mut out_buf = [0u8; 512];

        // 1. Default anonymous handler (`dev_user: None`)
        let anon_server = GitServiceHandler::default().into_server();
        let auth_req = HttpRequest::from_uri(HttpMethod::Get, API_AUTH_STATUS_PATH, None, &[]);
        let mut writer = BackwardWriter::new(&mut out_buf);
        let anon_auth_resp = anon_server
            .call_http(&auth_req, &mut scratch, &mut writer)
            .expect("matched /api/v1/auth/status")
            .expect("ok response");
        assert_eq!(anon_auth_resp.status_code, 200);
        let anon_auth_view = GetAuthStatusResponseView::from_bytes(anon_auth_resp.body).unwrap();
        assert!(!anon_auth_view.authenticated().unwrap());
        assert_eq!(anon_auth_view.username().unwrap(), "");
        assert_eq!(anon_auth_view.ssh_host().unwrap(), "localhost");

        let repos_req = HttpRequest::from_uri(HttpMethod::Get, API_REPOSITORIES_PATH, None, &[]);
        let mut writer = BackwardWriter::new(&mut out_buf);
        let anon_repos_resp = anon_server
            .call_http(&repos_req, &mut scratch, &mut writer)
            .expect("matched /api/v1/repositories")
            .expect("ok response");
        assert_eq!(anon_repos_resp.status_code, 200);
        let anon_repos_view =
            ListRepositoriesResponseView::from_bytes(anon_repos_resp.body).unwrap();
        assert_eq!(anon_repos_view.authenticated_user().unwrap(), "");
        assert_eq!(anon_repos_view.ssh_host().unwrap(), "localhost");

        // 2. Authenticated handler (`dev_user: Some("charles")`)
        let cfg = ServerConfig {
            ssh_host: String::from("git.team.internal"),
            dev_user: Some(String::from("charles")),
            ..ServerConfig::default()
        };
        let server = GitServiceHandler::new(cfg).into_server();

        let mut writer = BackwardWriter::new(&mut out_buf);
        let auth_resp = server
            .call_http(&auth_req, &mut scratch, &mut writer)
            .expect("matched /api/v1/auth/status")
            .expect("ok response");
        assert_eq!(auth_resp.status_code, 200);
        let auth_view = GetAuthStatusResponseView::from_bytes(auth_resp.body).unwrap();
        assert!(auth_view.authenticated().unwrap());
        assert_eq!(auth_view.username().unwrap(), "charles");
        assert_eq!(auth_view.ssh_host().unwrap(), "git.team.internal");

        let mut writer = BackwardWriter::new(&mut out_buf);
        let repos_resp = server
            .call_http(&repos_req, &mut scratch, &mut writer)
            .expect("matched /api/v1/repositories")
            .expect("ok response");
        assert_eq!(repos_resp.status_code, 200);
        let repos_view = ListRepositoriesResponseView::from_bytes(repos_resp.body).unwrap();
        assert_eq!(repos_view.authenticated_user().unwrap(), "charles");
        assert_eq!(repos_view.ssh_host().unwrap(), "git.team.internal");
        assert_eq!(repos_view.repositories().count(), 0);
    }

    #[test]
    fn verifies_ed25519_and_options_prefixed_authorized_keys_and_rejects_invalid_tokens() {
        let temp = TempRoot::new("sshsig-verify");
        let (alice_priv, alice_pub) = test_ed25519_keypair(0x11);
        let (other_priv, _other_pub) = test_ed25519_keypair(0x22);

        // Include comments, blank lines, and options prefix with quoted spaces
        let ak_contents = format!(
            "# Authorized keys for alice\n\ncommand=\"/bin/false --arg\",no-port-forwarding,restrict {alice_pub} alice@laptop\n"
        );
        write_authorized_keys(temp.path(), "alice", &ak_contents, 0o640);

        let now = 1_700_000_000;
        let max_ttl = 2_592_000;
        let valid_payload = format_token_payload("alice", now + 3_600).unwrap();
        let (valid_pem, valid_token) =
            sign_token_with_key(&alice_priv, SSH_SIG_NAMESPACE, &valid_payload);

        // 1. Valid signature verifies cleanly
        let verified_user =
            verify_bearer_token(temp.path(), &valid_token, now, max_ttl).expect("verify alice");
        assert_eq!(verified_user, "alice");

        // 2. Expired token is rejected
        let expired_payload = format_token_payload("alice", now).unwrap();
        let (_, expired_token) =
            sign_token_with_key(&alice_priv, SSH_SIG_NAMESPACE, &expired_payload);
        assert_eq!(
            verify_bearer_token(temp.path(), &expired_token, now, max_ttl),
            Err(AuthError::Token(TokenError::TokenExpired))
        );

        // 3. Excessive TTL token is rejected
        let ttl_payload = format_token_payload("alice", now + max_ttl + 1).unwrap();
        let (_, ttl_token) = sign_token_with_key(&alice_priv, SSH_SIG_NAMESPACE, &ttl_payload);
        assert_eq!(
            verify_bearer_token(temp.path(), &ttl_token, now, max_ttl),
            Err(AuthError::Token(TokenError::TokenTtlExceeded))
        );

        // 4. Wrong namespace ("git" instead of "ro-git") is rejected
        let (_, wrong_ns_token) = sign_token_with_key(&alice_priv, "git", &valid_payload);
        assert_eq!(
            verify_bearer_token(temp.path(), &wrong_ns_token, now, max_ttl),
            Err(AuthError::InvalidSignatureNamespace(String::from("git")))
        );

        // 5. Tampered payload (signed for alice, payload claims bob or different exp) is rejected
        let tampered_payload = format_token_payload("alice", now + 7_200).unwrap();
        let tampered_token = encode_bearer_token(&tampered_payload, &valid_pem).unwrap();
        assert_eq!(
            verify_bearer_token(temp.path(), &tampered_token, now, max_ttl),
            Err(AuthError::SignatureVerificationFailed)
        );

        // 6. Unauthorized key is rejected
        let (_, unauth_token) = sign_token_with_key(&other_priv, SSH_SIG_NAMESPACE, &valid_payload);
        assert_eq!(
            verify_bearer_token(temp.path(), &unauth_token, now, max_ttl),
            Err(AuthError::SignatureVerificationFailed)
        );

        // 7. World-writable / unsafe mode on authorized_keys is rejected
        let ak_path = temp.path().join("users/alice/authorized_keys");
        fs::set_permissions(&ak_path, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(matches!(
            verify_bearer_token(temp.path(), &valid_token, now, max_ttl),
            Err(AuthError::UnsafeAuthorizedKeys(_))
        ));

        // 8. Symlinked authorized_keys is rejected
        fs::remove_file(&ak_path).unwrap();
        let target_ak = temp.path().join("real_ak");
        fs::write(&target_ak, &ak_contents).unwrap();
        fs::set_permissions(&target_ak, fs::Permissions::from_mode(0o600)).unwrap();
        std::os::unix::fs::symlink(&target_ak, &ak_path).unwrap();
        assert!(matches!(
            verify_bearer_token(temp.path(), &valid_token, now, max_ttl),
            Err(AuthError::UnsafeAuthorizedKeys(_))
        ));
    }

    const TEST_RSA_SSH_PUBLIC_KEY: &str = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDFSJ68FsqScY/+Rh+V7r9UFxe4vZfOKan7PzyIMjKTJk5UmzV4lym6SjGZVOh84OP5QjNqHwuoJK2qQViIVyelkhzVkC4RM+ga06u+ypqRcBse2P/TCLpNRTM3Lq13UWvJ4DxPzbwGwSxaG+uuPokyDLIxgfpDIV+cVGcYypyfX3AKb2LZESSipTDcx1bEK+ecwqEEnlSq+h42BjLmAn6zU+LcNEdMCLFlVs2GrXVeyAh26CPDj06/IGGkeXL/EvCE7TYBk5Hb5IPAQghYqmIwDDO/qml8ayM1jlqLvqeXgBw2pEcv1PJq5LO5TkT5l8JyNIT3Wiw+OLATUVXTGwbZ alice@rsa";

    const TEST_RSA_SSHSIG_SHA512_PEM: &str = "-----BEGIN SSH SIGNATURE-----\n\
U1NIU0lHAAAAAQAAARcAAAAHc3NoLXJzYQAAAAMBAAEAAAEBAMVInrwWypJxj/5GH5Xuv1\n\
QXF7i9l84pqfs/PIgyMpMmTlSbNXiXKbpKMZlU6Hzg4/lCM2ofC6gkrapBWIhXJ6WSHNWQ\n\
LhEz6BrTq77KmpFwGx7Y/9MIuk1FMzcurXdRa8ngPE/NvAbBLFob664+iTIMsjGB+kMhX5\n\
xUZxjKnJ9fcApvYtkRJKKlMNzHVsQr55zCoQSeVKr6HjYGMuYCfrNT4tw0R0wIsWVWzYat\n\
dV7ICHboI8OPTr8gYaR5cv8S8ITtNgGTkdvkg8BCCFiqYjAMM7+qaXxrIzWOWou+p5eAHD\n\
akRy/U8mrks7lORPmXwnI0hPdaLD44sBNRVdMbBtkAAAAGcm8tZ2l0AAAAAAAAAAZzaGE1\n\
MTIAAAEUAAAADHJzYS1zaGEyLTUxMgAAAQBumR4C6AHBEvPG5YsS57b5CpnHYOdo9z5/sB\n\
+spIAQi1FMSdIpzVR0dT0hg3VxAF9W4l1WblEolA0WO12tv1BFbVMHqQnfk8Al7/zpb8lu\n\
NF9RvQFh48KOxV3BT/gxw7pq/ZzXk9PMs5KQtAj8jV4SSxVpCpGyey2EDiCmw85UXDsFIV\n\
cjH12V083KagbUEHQGjIKEQcH9Tz8dqsGKacRvtDd7ufnYDzed+wAg3/vRf86ZzRpjqbOq\n\
2Z22F9G8MDzLiXEDCvMoVHQm/M5vpwAjve460UUb7hoslhaH8yanQFnvHR1MgTXDaK8Omi\n\
KWTzO7/JyBmlqrmZyzkhxvLMty\n\
-----END SSH SIGNATURE-----\n";

    const TEST_RSA_SSHSIG_SHA256_PEM: &str = "-----BEGIN SSH SIGNATURE-----\n\
U1NIU0lHAAAAAQAAARcAAAAHc3NoLXJzYQAAAAMBAAEAAAEBAMVInrwWypJxj/5GH5Xuv1\n\
QXF7i9l84pqfs/PIgyMpMmTlSbNXiXKbpKMZlU6Hzg4/lCM2ofC6gkrapBWIhXJ6WSHNWQ\n\
LhEz6BrTq77KmpFwGx7Y/9MIuk1FMzcurXdRa8ngPE/NvAbBLFob664+iTIMsjGB+kMhX5\n\
xUZxjKnJ9fcApvYtkRJKKlMNzHVsQr55zCoQSeVKr6HjYGMuYCfrNT4tw0R0wIsWVWzYat\n\
dV7ICHboI8OPTr8gYaR5cv8S8ITtNgGTkdvkg8BCCFiqYjAMM7+qaXxrIzWOWou+p5eAHD\n\
akRy/U8mrks7lORPmXwnI0hPdaLD44sBNRVdMbBtkAAAAGcm8tZ2l0AAAAAAAAAAZzaGEy\n\
NTYAAAEUAAAADHJzYS1zaGEyLTI1NgAAAQCBQQsG7pZ86H5rrF/YKLVbQeiSA5n4vSksZc\n\
VGL35sSqat9Ve3hu0cuHWA46L9ZRL8yzIsWVSVn+dzTZjTne9bKYpP5CtEAaFJdUpicJWo\n\
SGmGHmiY7bYIlqLY0gxOTxNT72dnWyt6lCAU+EHgkc+s7+Y0Qfa3/FZ9SrNAOYJYTNdVNX\n\
lmqMhh55Bec4l5WOy3o8uK0mbgY1gcmnJUbFuMtydB6jEUQiTOgKrCfI0e38TlbjMVPnAw\n\
DOYw7nOFX6AO8ngIFv1xQOGVQ05XH239IlYNCpR9ed2Edd2kZbogIKJycBzMxrOxxX8knM\n\
TBcf2gHOcj9Ai0txbeMkVRWweq\n\
-----END SSH SIGNATURE-----\n";

    #[test]
    fn verifies_ed25519_and_rsa_sshsig_signatures() {
        let temp = TempRoot::new("sshsig-ed25519-and-rsa");
        let now = 1_700_000_000;
        let max_ttl = 2_592_000;
        let payload = format_token_payload("alice", now + 3_600).unwrap();

        let (ed_priv, ed_pub) = test_ed25519_keypair(0x33);

        write_authorized_keys(
            temp.path(),
            "alice",
            &format!("{ed_pub} alice@ed25519\n{TEST_RSA_SSH_PUBLIC_KEY}\n"),
            0o600,
        );

        // 1. Verify Ed25519 signatures with both SHA-256 and SHA-512
        for hash_alg in [HashAlg::Sha256, HashAlg::Sha512] {
            let sig = ed_priv
                .sign(SSH_SIG_NAMESPACE, hash_alg, payload.as_bytes())
                .expect("sign ed25519 payload");
            let pem = sig.to_pem(LineEnding::LF).expect("encode sshsig pem");
            let token = encode_bearer_token(&payload, &pem).unwrap();
            let user = verify_bearer_token(temp.path(), &token, now, max_ttl)
                .expect("verify ed25519 signature");
            assert_eq!(user, "alice");
        }

        // 2. Verify 2048-bit RSA signatures (rsa-sha2-512 and rsa-sha2-256)
        for rsa_pem in [TEST_RSA_SSHSIG_SHA512_PEM, TEST_RSA_SSHSIG_SHA256_PEM] {
            let token = encode_bearer_token(&payload, rsa_pem).unwrap();
            let user = verify_bearer_token(temp.path(), &token, now, max_ttl)
                .expect("verify rsa signature");
            assert_eq!(user, "alice");

            // Tampered payload with valid RSA signature must be rejected
            let tampered_payload = format_token_payload("alice", now + 3_601).unwrap();
            let tampered_token = encode_bearer_token(&tampered_payload, rsa_pem).unwrap();
            assert_eq!(
                verify_bearer_token(temp.path(), &tampered_token, now, max_ttl),
                Err(AuthError::SignatureVerificationFailed)
            );
        }

        // 3. Also test against the external `ssh-keygen` CLI when present on PATH
        if Command::new("ssh-keygen").arg("-V").output().is_ok() {
            let key_dir = temp.path().join("keys");
            fs::create_dir_all(&key_dir).unwrap();
            let ed_key = key_dir.join("id_ed25519");
            let status_ed = Command::new("ssh-keygen")
                .args(["-q", "-t", "ed25519", "-N", "", "-f"])
                .arg(&ed_key)
                .status()
                .expect("run ssh-keygen ed25519");
            assert!(status_ed.success());

            let ed_cli_pub = fs::read_to_string(key_dir.join("id_ed25519.pub")).unwrap();
            write_authorized_keys(temp.path(), "alice", &ed_cli_pub, 0o600);

            let mut child = Command::new("ssh-keygen")
                .args(["-Y", "sign", "-n", SSH_SIG_NAMESPACE, "-f"])
                .arg(&ed_key)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("spawn ssh-keygen -Y sign");
            child
                .stdin
                .take()
                .unwrap()
                .write_all(payload.as_bytes())
                .unwrap();
            let out = child.wait_with_output().unwrap();
            assert!(out.status.success());
            let pem = String::from_utf8(out.stdout).unwrap();
            let token = encode_bearer_token(&payload, &pem).unwrap();
            let user = verify_bearer_token(temp.path(), &token, now, max_ttl)
                .expect("verify ssh-keygen signature");
            assert_eq!(user, "alice");
        }
    }

    #[test]
    fn resolves_credentials_and_filters_repositories_by_visibility_and_query() {
        let temp = TempRoot::new("repo-discovery");
        let root = temp.path();

        // Provision /etc/passwd and /etc/group inside temp root
        let etc_dir = root.join("etc");
        fs::create_dir_all(&etc_dir).unwrap();
        fs::write(
            etc_dir.join("passwd"),
            "alice:x:2001:2001::/users/alice:/usr/bin/git-shell\nbob:x:2002:2002::/users/bob:/usr/bin/git-shell\n",
        )
        .unwrap();
        fs::write(
            etc_dir.join("group"),
            "alice:x:2001:\nbob:x:2002:\nteam-core:x:3001:alice\nteam-ops:x:3002:bob\n",
        )
        .unwrap();

        // Create repositories
        let repos = [
            "users/alice/public/dotfiles.git",
            "users/alice/private/journal.git",
            "users/bob/public/blog.git",
            "users/bob/private/finances.git",
            "teams/core/public/ro-git.git",
            "teams/core/private/roadmap.git",
            "teams/ops/private/runbooks.git",
        ];
        for rel in repos {
            fs::create_dir_all(root.join(rel)).unwrap();
        }
        fs::write(root.join("teams/core/members"), "alice\n").unwrap();
        fs::write(root.join("teams/ops/members"), "bob\n").unwrap();

        // Symlinked repo must be rejected
        std::os::unix::fs::symlink(
            root.join("users/alice/public/dotfiles.git"),
            root.join("users/alice/public/symlinked.git"),
        )
        .unwrap();

        // 1. Anonymous user sees only public repositories
        let anon_creds = resolve_user_credentials(root, Some(&etc_dir), None, 65_534).unwrap();
        assert_eq!(anon_creds.uid, 65_534);
        let anon_repos = discover_repositories(
            root,
            "git.example.com",
            &anon_creds,
            &RepositoryFilter::default(),
        );
        let anon_paths: Vec<_> = anon_repos
            .iter()
            .map(|r| r.canonical_path.as_str())
            .collect();
        assert_eq!(
            anon_paths,
            vec![
                "/teams/core/public/ro-git.git",
                "/users/alice/public/dotfiles.git",
                "/users/bob/public/blog.git",
            ]
        );
        assert_eq!(
            anon_repos[0].clone_command,
            "git clone ssh://git.example.com/teams/core/public/ro-git.git"
        );

        // 2. Alice sees all public repos + her own private repos + team `core` private repos (not bob's or `ops` private)
        let alice_creds =
            resolve_user_credentials(root, Some(&etc_dir), Some("alice"), 65_534).unwrap();
        assert_eq!(alice_creds.uid, 2001);
        assert_eq!(alice_creds.gid, 2001);
        assert_eq!(alice_creds.supplementary_gids, vec![3001]);
        assert_eq!(alice_creds.team_names, vec![String::from("core")]);

        let alice_repos = discover_repositories(
            root,
            "git.example.com",
            &alice_creds,
            &RepositoryFilter::default(),
        );
        let alice_paths: Vec<_> = alice_repos
            .iter()
            .map(|r| r.canonical_path.as_str())
            .collect();
        assert_eq!(
            alice_paths,
            vec![
                "/teams/core/private/roadmap.git",
                "/teams/core/public/ro-git.git",
                "/users/alice/private/journal.git",
                "/users/alice/public/dotfiles.git",
                "/users/bob/public/blog.git",
            ]
        );
        assert_eq!(
            alice_repos[0].clone_command,
            "git clone ssh://alice@git.example.com/teams/core/private/roadmap.git"
        );

        // 3. Test scope, owner, visibility, and case-insensitive query filters
        let filtered = discover_repositories(
            root,
            "git.example.com",
            &alice_creds,
            &RepositoryFilter {
                scope: "teams",
                owner: "core",
                visibility: "private",
                query: "ROAD",
            },
        );
        assert_eq!(filtered.len(), 1);
        assert_eq!(
            filtered[0].canonical_path,
            "/teams/core/private/roadmap.git"
        );

        // 4. GitServiceHandler with Authorization: Bearer <token> metadata
        let (alice_priv, alice_pub) = test_ed25519_keypair(0x33);
        write_authorized_keys(root, "alice", &format!("{alice_pub}\n"), 0o600);
        let exp = current_unix_secs() + 3_600;
        let payload = format_token_payload("alice", exp).unwrap();
        let (_, bearer_tok) = sign_token_with_key(&alice_priv, SSH_SIG_NAMESPACE, &payload);
        let auth_header_val = format!("Bearer {bearer_tok}");

        let server = GitServiceHandler::new(ServerConfig {
            root_dir: root.to_string_lossy().into_owned(),
            ssh_host: String::from("git.example.com"),
            ..ServerConfig::default()
        })
        .into_server();

        let mut ctx = RpcContext::<roto_grpc::FixedMetadata>::new();
        ctx.request
            .insert("authorization", &auth_header_val)
            .expect("insert authorization header");
        let mut out_buf = [0u8; 4096];

        let mut meta = ctx.metadata();
        let mut writer = BackwardWriter::new(&mut out_buf);
        server
            .call_unary(&mut meta, "GetAuthStatus", &[], &mut writer)
            .expect("GetAuthStatus unary call");
        let lpm = writer.finish().unwrap();
        let auth_view = GetAuthStatusResponseView::from_bytes(&lpm[5..]).unwrap();
        assert!(auth_view.authenticated().unwrap());
        assert_eq!(auth_view.username().unwrap(), "alice");

        let mut meta = ctx.metadata();
        let mut writer = BackwardWriter::new(&mut out_buf);
        server
            .call_unary(&mut meta, "ListRepositories", &[], &mut writer)
            .expect("ListRepositories unary call");
        let lpm = writer.finish().unwrap();
        let repos_view = ListRepositoriesResponseView::from_bytes(&lpm[5..]).unwrap();
        assert_eq!(repos_view.authenticated_user().unwrap(), "alice");
        assert_eq!(repos_view.repositories().count(), 5);

        // Invalid bearer token returns GrpcCode::Unauthenticated
        let mut bad_ctx = RpcContext::<roto_grpc::FixedMetadata>::new();
        bad_ctx
            .request
            .insert("authorization", "Bearer invalid.token")
            .unwrap();
        let mut bad_meta = bad_ctx.metadata();
        let mut writer = BackwardWriter::new(&mut out_buf);
        let err = server
            .call_unary(&mut bad_meta, "GetAuthStatus", &[], &mut writer)
            .expect_err("invalid token must fail");
        assert_eq!(err.code, GrpcCode::Unauthenticated);

        for method in [
            "GetRepository",
            "GetTree",
            "GetBlob",
            "ListCommits",
            "GetCommit",
        ] {
            let mut meta = ctx.metadata();
            let mut writer = BackwardWriter::new(&mut out_buf);
            let err = server
                .call_unary(&mut meta, method, &[], &mut writer)
                .expect_err("empty object inspection RPC request must return InvalidArgument");
            assert_eq!(err.code, GrpcCode::InvalidArgument, "method {method}");
        }
    }

    fn run_git_test_cmd(cwd: &Path, args: &[&str]) {
        let out = Command::new("git")
            .current_dir(cwd)
            .args(args)
            .env("GIT_AUTHOR_NAME", "Alice")
            .env("GIT_AUTHOR_EMAIL", "alice@example.com")
            .env("GIT_AUTHOR_DATE", "1700000000 +0000")
            .env("GIT_COMMITTER_NAME", "Alice")
            .env("GIT_COMMITTER_EMAIL", "alice@example.com")
            .env("GIT_COMMITTER_DATE", "1700000100 +0000")
            .output()
            .expect("execute git command in test");
        assert!(
            out.status.success(),
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&out.stderr)
        );
    }

    #[test]
    fn inspects_bare_repositories_trees_blobs_commits_and_enforces_security_checks() {
        let temp = TempRoot::new("git-reader");
        let root = temp.path();

        // 1. Provision an empty/unborn bare repository
        let unborn_dir = root.join("users/alice/public/empty.git");
        fs::create_dir_all(&unborn_dir).unwrap();
        run_git_test_cmd(&unborn_dir, &["init", "--bare", "--initial-branch=main"]);

        // 2. Provision a populated bare repository via a temporary working tree
        let bare_dir = root.join("users/alice/public/project.git");
        fs::create_dir_all(&bare_dir).unwrap();
        run_git_test_cmd(&bare_dir, &["init", "--bare", "--initial-branch=main"]);

        let priv_dir = root.join("users/alice/private/secret.git");
        fs::create_dir_all(&priv_dir).unwrap();
        run_git_test_cmd(&priv_dir, &["init", "--bare", "--initial-branch=main"]);

        let work_dir = root.join("work");
        fs::create_dir_all(&work_dir).unwrap();
        run_git_test_cmd(&work_dir, &["init", "--initial-branch=main"]);
        run_git_test_cmd(&work_dir, &["config", "user.name", "Alice"]);
        run_git_test_cmd(&work_dir, &["config", "user.email", "alice@example.com"]);

        fs::write(work_dir.join("README.md"), "# Project\nHello world\n").unwrap();
        fs::create_dir_all(work_dir.join("src/nested")).unwrap();
        fs::write(work_dir.join("src/lib.rs"), "pub fn add(a: i32, b: i32) -> i32 { a + b }\n")
            .unwrap();
        fs::write(work_dir.join("src/nested/mod.rs"), "// nested mod\n").unwrap();
        fs::write(work_dir.join("assets.bin"), b"\x89PNG\r\n\x1a\n\x00\x01\x02\x03").unwrap();
        fs::write(work_dir.join("old_name.txt"), "rename me line 1\nrename me line 2\n").unwrap();
        fs::write(work_dir.join("to_delete.txt"), "goodbye\n").unwrap();

        run_git_test_cmd(&work_dir, &["add", "."]);
        run_git_test_cmd(&work_dir, &["commit", "-m", "Initial commit\n\nDetailed body."]);
        run_git_test_cmd(&work_dir, &["tag", "v0.1.0"]);

        // Second commit: modify README.md, rename old_name.txt -> new_name.txt, delete to_delete.txt, add annotated tag
        fs::write(
            work_dir.join("README.md"),
            "# Project\nHello world\nUpdated line\n",
        )
        .unwrap();
        run_git_test_cmd(&work_dir, &["mv", "old_name.txt", "new_name.txt"]);
        run_git_test_cmd(&work_dir, &["rm", "to_delete.txt"]);
        run_git_test_cmd(&work_dir, &["add", "-A"]);
        run_git_test_cmd(&work_dir, &["commit", "-m", "Second commit"]);
        run_git_test_cmd(&work_dir, &["tag", "-a", "v1.0.0", "-m", "Release 1.0.0"]);
        run_git_test_cmd(&work_dir, &["branch", "dev"]);

        let bare_path_str = bare_dir.to_string_lossy().into_owned();
        run_git_test_cmd(&work_dir, &["remote", "add", "origin", &bare_path_str]);
        run_git_test_cmd(&work_dir, &["push", "origin", "main", "dev", "--tags"]);

        let priv_path_str = priv_dir.to_string_lossy().into_owned();
        run_git_test_cmd(&work_dir, &["remote", "add", "priv", &priv_path_str]);
        run_git_test_cmd(&work_dir, &["push", "priv", "main"]);

        let anon_creds = UserCredentials {
            username: None,
            uid: 65_534,
            gid: 65_534,
            supplementary_gids: Vec::new(),
            team_names: Vec::new(),
        };
        let alice_creds = UserCredentials {
            username: Some(String::from("alice")),
            uid: 1001,
            gid: 1001,
            supplementary_gids: Vec::new(),
            team_names: Vec::new(),
        };

        // 3. Test empty/unborn bare repository
        let empty_repo = inspect_repository(
            root,
            "git.example.com",
            &anon_creds,
            "users",
            "alice",
            "public",
            "empty",
            "",
        )
        .expect("empty bare repo GetRepository must succeed");
        assert_eq!(empty_repo.head_ref, "main");
        assert_eq!(empty_repo.head_oid, "");
        assert_eq!(empty_repo.resolved_revision, "");
        assert!(empty_repo.branches.is_empty());
        assert!(empty_repo.tags.is_empty());
        assert!(empty_repo.entries.is_empty());

        let empty_commits = inspect_commits(
            root,
            "git.example.com",
            &anon_creds,
            "users",
            "alice",
            "public",
            "empty",
            "",
            "",
            50,
            0,
        )
        .expect("empty bare repo ListCommits with default revision must succeed");
        assert!(empty_commits.commits.is_empty());
        assert!(!empty_commits.has_more);

        // Explicit revision on empty repo returns NotFound
        assert_eq!(
            inspect_repository(
                root,
                "git.example.com",
                &anon_creds,
                "users",
                "alice",
                "public",
                "empty",
                "main",
            )
            .unwrap_err()
            .0,
            GrpcCode::NotFound
        );

        // 4. Test GetRepository on populated repo
        let repo_insp = inspect_repository(
            root,
            "git.example.com",
            &alice_creds,
            "users",
            "alice",
            "public",
            "project.git",
            "",
        )
        .expect("inspect populated project repo");
        assert_eq!(repo_insp.repository.name, "project");
        assert_eq!(
            repo_insp.repository.clone_command,
            "git clone ssh://alice@git.example.com/users/alice/public/project.git"
        );
        assert_eq!(repo_insp.head_ref, "main");
        assert_eq!(repo_insp.head_oid.len(), 40);
        assert_eq!(repo_insp.resolved_revision, "main");
        let branch_names: Vec<&str> = repo_insp.branches.iter().map(|b| b.name.as_str()).collect();
        assert_eq!(branch_names, vec!["dev", "main"]);
        let tag_names: Vec<&str> = repo_insp.tags.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(tag_names, vec!["v0.1.0", "v1.0.0"]);
        // Annotated tag v1.0.0 must resolve to the target commit OID (head_oid)
        assert_eq!(repo_insp.tags[1].oid, repo_insp.head_oid);
        // Root entries must be sorted with directories first, then files by name
        let entry_kinds_names: Vec<(&str, &str)> = repo_insp
            .entries
            .iter()
            .map(|e| (e.kind.as_str(), e.name.as_str()))
            .collect();
        assert_eq!(
            entry_kinds_names,
            vec![
                ("dir", "src"),
                ("file", "README.md"),
                ("file", "assets.bin"),
                ("file", "new_name.txt"),
            ]
        );

        // 5. Test GetTree at nested subdirectory
        let tree_insp = inspect_tree(
            root,
            "git.example.com",
            &anon_creds,
            "users",
            "alice",
            "public",
            "project",
            "v1.0.0",
            "src",
        )
        .expect("inspect src tree");
        assert_eq!(tree_insp.revision, "v1.0.0");
        assert_eq!(tree_insp.path, "src");
        let src_entries: Vec<(&str, &str, &str)> = tree_insp
            .entries
            .iter()
            .map(|e| (e.kind.as_str(), e.name.as_str(), e.path.as_str()))
            .collect();
        assert_eq!(
            src_entries,
            vec![
                ("dir", "nested", "src/nested"),
                ("file", "lib.rs", "src/lib.rs"),
            ]
        );

        // Calling GetTree on a file path must return NotFound
        assert_eq!(
            inspect_tree(
                root,
                "git.example.com",
                &anon_creds,
                "users",
                "alice",
                "public",
                "project",
                "HEAD",
                "README.md",
            )
            .unwrap_err()
            .0,
            GrpcCode::NotFound
        );

        // 6. Test GetBlob for text and binary blobs
        let text_blob = inspect_blob(
            root,
            "git.example.com",
            &anon_creds,
            "users",
            "alice",
            "public",
            "project",
            "v0.1.0",
            "README.md",
        )
        .expect("inspect text blob at v0.1.0");
        assert!(!text_blob.is_binary);
        assert!(!text_blob.truncated);
        assert_eq!(text_blob.content, b"# Project\nHello world\n");

        let bin_blob = inspect_blob(
            root,
            "git.example.com",
            &anon_creds,
            "users",
            "alice",
            "public",
            "project",
            "HEAD",
            "assets.bin",
        )
        .expect("inspect binary blob");
        assert!(bin_blob.is_binary);
        assert!(!bin_blob.truncated);
        assert_eq!(bin_blob.content, b"\x89PNG\r\n\x1a\n\x00\x01\x02\x03");

        // Calling GetBlob on a directory or empty path fails appropriately
        assert_eq!(
            inspect_blob(
                root,
                "git.example.com",
                &anon_creds,
                "users",
                "alice",
                "public",
                "project",
                "HEAD",
                "src",
            )
            .unwrap_err()
            .0,
            GrpcCode::NotFound
        );
        assert_eq!(
            inspect_blob(
                root,
                "git.example.com",
                &anon_creds,
                "users",
                "alice",
                "public",
                "project",
                "HEAD",
                "",
            )
            .unwrap_err()
            .0,
            GrpcCode::InvalidArgument
        );

        // 7. Test ListCommits with pagination and path filter
        let page1 = inspect_commits(
            root,
            "git.example.com",
            &anon_creds,
            "users",
            "alice",
            "public",
            "project",
            "main",
            "",
            1,
            0,
        )
        .expect("list commits page 1");
        assert_eq!(page1.commits.len(), 1);
        assert!(page1.has_more);
        assert_eq!(page1.commits[0].subject, "Second commit");

        let page2 = inspect_commits(
            root,
            "git.example.com",
            &anon_creds,
            "users",
            "alice",
            "public",
            "project",
            "main",
            "",
            1,
            1,
        )
        .expect("list commits page 2");
        assert_eq!(page2.commits.len(), 1);
        assert!(!page2.has_more);
        assert_eq!(page2.commits[0].subject, "Initial commit");
        assert_eq!(page2.commits[0].message, "Initial commit\n\nDetailed body.");

        // 8. Test GetCommit diff statuses (modified, renamed, deleted)
        let commit_detail = inspect_commit(
            root,
            "git.example.com",
            &anon_creds,
            "users",
            "alice",
            "public",
            "project",
            &page1.commits[0].oid,
        )
        .expect("inspect second commit");
        assert_eq!(commit_detail.commit.subject, "Second commit");
        assert_eq!(commit_detail.total_additions, 1);
        assert_eq!(commit_detail.total_deletions, 1);
        assert!(commit_detail.patch.contains("diff --git"));
        let statuses: Vec<(&str, &str, &str)> = commit_detail
            .files
            .iter()
            .map(|f| (f.status.as_str(), f.old_path.as_str(), f.path.as_str()))
            .collect();
        assert_eq!(
            statuses,
            vec![
                ("modified", "", "README.md"),
                ("renamed", "old_name.txt", "new_name.txt"),
                ("deleted", "", "to_delete.txt"),
            ]
        );

        // 9. Test private repository visibility access control & security rejections
        assert_eq!(
            inspect_repository(
                root,
                "git.example.com",
                &anon_creds,
                "users",
                "alice",
                "private",
                "secret",
                "",
            )
            .unwrap_err()
            .0,
            GrpcCode::NotFound
        );
        assert!(inspect_repository(
            root,
            "git.example.com",
            &alice_creds,
            "users",
            "alice",
            "private",
            "secret",
            "",
        )
        .is_ok());

        // Invalid revision (--flag injection) and path traversal must return InvalidArgument
        assert_eq!(
            inspect_repository(
                root,
                "git.example.com",
                &anon_creds,
                "users",
                "alice",
                "public",
                "project",
                "--output=/tmp/pwn",
            )
            .unwrap_err()
            .0,
            GrpcCode::InvalidArgument
        );
        assert_eq!(
            inspect_tree(
                root,
                "git.example.com",
                &anon_creds,
                "users",
                "alice",
                "public",
                "project",
                "HEAD",
                "../secret",
            )
            .unwrap_err()
            .0,
            GrpcCode::InvalidArgument
        );
    }
}
