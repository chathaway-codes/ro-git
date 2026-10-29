//! `ro-git-server` backend library implementing the `roto-grpc` `GitService`,
//! OpenSSH `SSHSIG` stateless token verification, user/team credential resolution,
//! and privilege-separated `git-worker` IPC and repository discovery.

use std::fmt;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use ro_git_proto::grpc::ro_git::v1::git_service::{GitService, GitServiceServer};
use ro_git_proto::ro_git::v1::{
    worker_request, worker_response, GetAuthStatusRequestView, GetAuthStatusResponseBuilder,
    ListRepositoriesRequestView, ListRepositoriesResponseBuilder, WorkerRequestBuilder,
    WorkerRequestView, WorkerResponseBuilder, WorkerResponseView,
};
use ro_git_proto::{
    decode_bearer_token, format_canonical_path, format_clone_command, format_ssh_url,
    is_valid_identifier, is_valid_scope, is_valid_visibility, normalize_ssh_host,
    validate_token_claims, TokenError, SCOPE_TEAMS, SCOPE_USERS, SSH_SIG_NAMESPACE,
    VISIBILITY_PRIVATE, VISIBILITY_PUBLIC,
};
use roto_grpc::{GrpcCode, GrpcStatus, RpcMetadata};
use ssh_key::{PublicKey, SshSig};

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
    let mut buf = vec![0u8; 1024];
    let mut builder = WorkerResponseBuilder::new(&mut buf);
    builder
        .write_error_message(message)
        .write_status_code(code as u32);
    builder
        .finish()
        .expect("worker error response fits in 1024-byte buffer")
        .to_vec()
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
            let mut buf = vec![0u8; 2048];
            let mut builder = WorkerResponseBuilder::new(&mut buf);
            builder
                .write_auth_status(|auth| {
                    auth.write_ssh_host(ssh_host);
                    if let Some(ref user) = creds.username {
                        auth.write_username(user).write_authenticated(true);
                    } else {
                        auth.write_username("").write_authenticated(false);
                    }
                })
                .write_status_code(GrpcCode::Ok as u32);
            match builder.finish() {
                Ok(bytes) => bytes.to_vec(),
                Err(_) => {
                    encode_worker_error(GrpcCode::ResourceExhausted, "worker buffer exhausted")
                }
            }
        }
        Ok(Some(worker_request::Command::ListRepositories(lr))) => {
            let filter = RepositoryFilter {
                scope: lr.scope().unwrap_or(""),
                owner: lr.owner().unwrap_or(""),
                visibility: lr.visibility().unwrap_or(""),
                query: lr.query().unwrap_or(""),
            };
            let repos = discover_repositories(root_dir, ssh_host, &creds, &filter);
            let mut buf = vec![0u8; 65_536];
            let mut builder = WorkerResponseBuilder::new(&mut buf);
            let mut overflow = false;
            builder
                .write_list_repositories(|list_resp| {
                    list_resp
                        .write_ssh_host(ssh_host)
                        .write_authenticated_user(creds.username.as_deref().unwrap_or(""));
                    for repo in repos.iter().rev() {
                        list_resp.write_repositories(|r| {
                            r.write_clone_command(&repo.clone_command)
                                .write_ssh_url(&repo.ssh_url)
                                .write_canonical_path(&repo.canonical_path)
                                .write_name(&repo.name)
                                .write_visibility(&repo.visibility)
                                .write_owner(&repo.owner)
                                .write_scope(&repo.scope);
                        });
                        if list_resp.check().is_err() {
                            overflow = true;
                            break;
                        }
                    }
                })
                .write_status_code(GrpcCode::Ok as u32);
            if overflow {
                return encode_worker_error(GrpcCode::ResourceExhausted, "worker buffer exhausted");
            }
            match builder.finish() {
                Ok(bytes) => bytes.to_vec(),
                Err(_) => {
                    encode_worker_error(GrpcCode::ResourceExhausted, "worker buffer exhausted")
                }
            }
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
        c if c == GrpcCode::PermissionDenied as u32 => {
            GrpcStatus::permission_denied("permission denied")
        }
        c if c == GrpcCode::ResourceExhausted as u32 => {
            GrpcStatus::resource_exhausted("worker response buffer exhausted")
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
    }
}
