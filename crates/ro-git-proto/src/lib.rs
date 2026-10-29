#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::borrow::ToOwned;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

#[rustfmt::skip]
pub mod generated;
pub use generated::*;

pub use generated::ro_git::v1;

/// Canonical gRPC and HTTP service route constants.
pub const API_AUTH_STATUS_PATH: &str = "/api/v1/auth/status";
pub const API_REPOSITORIES_PATH: &str = "/api/v1/repositories";

/// Valid top-level repository scopes in `/users/<user>` and `/teams/<team>`.
pub const SCOPE_USERS: &str = "users";
pub const SCOPE_TEAMS: &str = "teams";

/// Valid repository visibility tiers (`public` and `private`).
pub const VISIBILITY_PUBLIC: &str = "public";
pub const VISIBILITY_PRIVATE: &str = "private";

/// Canonical tree entry kind values used in `TreeEntry.kind`.
pub const TREE_KIND_FILE: &str = "file";
pub const TREE_KIND_DIR: &str = "dir";
pub const TREE_KIND_SYMLINK: &str = "symlink";
pub const TREE_KIND_SUBMODULE: &str = "submodule";

/// Canonical commit file diff status values used in `CommitFileDiff.status`.
pub const DIFF_STATUS_ADDED: &str = "added";
pub const DIFF_STATUS_MODIFIED: &str = "modified";
pub const DIFF_STATUS_DELETED: &str = "deleted";
pub const DIFF_STATUS_RENAMED: &str = "renamed";
pub const DIFF_STATUS_COPIED: &str = "copied";
pub const DIFF_STATUS_TYPECHANGE: &str = "typechange";

/// Default Git revision when none is explicitly provided.
pub const DEFAULT_REVISION: &str = "HEAD";

/// OpenSSH `SSHSIG` signature namespace used for stateless web tokens.
pub const SSH_SIG_NAMESPACE: &str = "ro-git";

/// Token payload version prefix (`ro-git:v1:<user>:<exp_unix>`).
pub const TOKEN_VERSION_PREFIX: &str = "ro-git:v1";

/// OpenSSH `SSHSIG` PEM header and footer markers.
pub const SSH_SIG_PEM_BEGIN: &str = "-----BEGIN SSH SIGNATURE-----";
pub const SSH_SIG_PEM_END: &str = "-----END SSH SIGNATURE-----";

const BASE64URL_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Decoded stateless bearer token components.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedToken {
    pub payload: String,
    pub sshsig_pem: String,
    pub username: String,
    pub exp_unix_secs: u64,
}

/// Errors produced when formatting, encoding, decoding, or validating a stateless bearer token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokenError {
    MalformedToken,
    InvalidBase64,
    InvalidUtf8,
    InvalidPayloadFormat,
    InvalidVersionPrefix,
    InvalidUsername,
    InvalidExpiration,
    InvalidSignaturePem,
    TokenExpired,
    TokenTtlExceeded,
}

impl fmt::Display for TokenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedToken => f.write_str("malformed bearer token"),
            Self::InvalidBase64 => f.write_str("invalid base64url encoding"),
            Self::InvalidUtf8 => f.write_str("invalid UTF-8 in token component"),
            Self::InvalidPayloadFormat => f.write_str("invalid token payload format"),
            Self::InvalidVersionPrefix => f.write_str("invalid token version prefix"),
            Self::InvalidUsername => f.write_str("invalid username in token payload"),
            Self::InvalidExpiration => f.write_str("invalid expiration timestamp in token payload"),
            Self::InvalidSignaturePem => f.write_str("invalid OpenSSH signature PEM block"),
            Self::TokenExpired => f.write_str("token has expired"),
            Self::TokenTtlExceeded => f.write_str("token expiration exceeds maximum allowed TTL"),
        }
    }
}

/// Returns `true` if `scope` is `"users"` or `"teams"`.
#[inline]
#[must_use]
pub fn is_valid_scope(scope: &str) -> bool {
    matches!(scope, SCOPE_USERS | SCOPE_TEAMS)
}

/// Returns `true` if `visibility` is `"public"` or `"private"`.
#[inline]
#[must_use]
pub fn is_valid_visibility(visibility: &str) -> bool {
    matches!(visibility, VISIBILITY_PUBLIC | VISIBILITY_PRIVATE)
}

/// Returns `true` if `ident` is a valid non-empty repository or owner identifier
/// matching `^[a-zA-Z0-9_-]+$`.
#[inline]
#[must_use]
pub fn is_valid_identifier(ident: &str) -> bool {
    !ident.is_empty()
        && ident
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// Returns `true` if `kind` is a canonical tree entry kind (`"file"`, `"dir"`, `"symlink"`, or `"submodule"`).
#[inline]
#[must_use]
pub fn is_valid_tree_kind(kind: &str) -> bool {
    matches!(
        kind,
        TREE_KIND_FILE | TREE_KIND_DIR | TREE_KIND_SYMLINK | TREE_KIND_SUBMODULE
    )
}

/// Maps a Git tree entry mode string (e.g. `"100644"`, `"040000"`) to its canonical `TREE_KIND_*` constant.
#[inline]
#[must_use]
pub fn tree_kind_from_mode(mode: &str) -> Option<&'static str> {
    match mode.trim() {
        "040000" | "40000" => Some(TREE_KIND_DIR),
        "120000" => Some(TREE_KIND_SYMLINK),
        "160000" => Some(TREE_KIND_SUBMODULE),
        "100644" | "100755" | "100664" => Some(TREE_KIND_FILE),
        _ => None,
    }
}

/// Returns `true` if `status` is a canonical commit file diff status.
#[inline]
#[must_use]
pub fn is_valid_diff_status(status: &str) -> bool {
    matches!(
        status,
        DIFF_STATUS_ADDED
            | DIFF_STATUS_MODIFIED
            | DIFF_STATUS_DELETED
            | DIFF_STATUS_RENAMED
            | DIFF_STATUS_COPIED
            | DIFF_STATUS_TYPECHANGE
    )
}

/// Returns `true` if `oid` is a valid 40-character hexadecimal Git object SHA-1.
#[inline]
#[must_use]
pub fn is_valid_oid(oid: &str) -> bool {
    oid.len() == 40 && oid.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Trims `revision` and falls back to [`DEFAULT_REVISION`] (`"HEAD"`) when empty.
#[inline]
#[must_use]
pub fn normalize_revision(revision: &str) -> &str {
    let trimmed = revision.trim();
    if trimmed.is_empty() {
        DEFAULT_REVISION
    } else {
        trimmed
    }
}

/// Returns `true` if `revision` is a safe, well-formed Git revision or ref name
/// (rejecting flag injection `-...`, control/whitespace characters, `..`, `@{`, `.lock`, etc.).
#[must_use]
pub fn is_valid_revision(revision: &str) -> bool {
    if revision.is_empty()
        || revision == "@"
        || revision.starts_with('-')
        || revision.starts_with('/')
        || revision.ends_with('/')
        || revision.contains("..")
        || revision.contains("//")
        || revision.contains("@{")
    {
        return false;
    }
    if revision
        .split('/')
        .any(|seg| seg.starts_with('.') || seg.ends_with('.') || seg.ends_with(".lock"))
    {
        return false;
    }
    revision.bytes().all(|b| {
        b > 0x20
            && b < 0x7f
            && !matches!(b, b'\\' | b':' | b'?' | b'*' | b'[' | b'~' | b'^')
    })
}

/// Normalizes a repository-relative tree or blob path, trimming leading/trailing `'/'`
/// and rejecting path traversal (`"."`, `".."`), backslashes, or NUL bytes.
#[must_use]
pub fn normalize_repo_path(path: &str) -> Option<String> {
    let trimmed = path.trim();
    if trimmed.contains('\\') || trimmed.contains('\0') {
        return None;
    }
    let mut normalized = String::new();
    for seg in trimmed.split('/').filter(|s| !s.is_empty()) {
        if seg == "." || seg == ".." {
            return None;
        }
        if !normalized.is_empty() {
            normalized.push('/');
        }
        normalized.push_str(seg);
    }
    Some(normalized)
}

/// Strips an optional trailing `.git` suffix from a repository directory or name.
#[inline]
#[must_use]
pub fn strip_git_suffix(name: &str) -> &str {
    name.strip_suffix(".git").unwrap_or(name)
}

/// Normalizes an SSH host string by trimming leading `ssh://` and trailing `/` characters.
#[inline]
#[must_use]
pub fn normalize_ssh_host(ssh_host: &str) -> &str {
    let trimmed = ssh_host.trim();
    let without_scheme = trimmed.strip_prefix("ssh://").unwrap_or(trimmed);
    let host = without_scheme.trim_end_matches('/');
    if host.is_empty() {
        "localhost"
    } else {
        host
    }
}

/// Formats the canonical 4-segment repository path:
/// `/<scope>/<owner>/<visibility>/<name>.git`
#[must_use]
pub fn format_canonical_path(scope: &str, owner: &str, visibility: &str, name: &str) -> String {
    let base = strip_git_suffix(name);
    format!("/{scope}/{owner}/{visibility}/{base}.git")
}

/// Formats the HTTP API path for `GetRepository`:
/// `/api/v1/repositories/<scope>/<owner>/<visibility>/<name>`
#[must_use]
pub fn format_repository_api_path(
    scope: &str,
    owner: &str,
    visibility: &str,
    name: &str,
) -> String {
    let base = strip_git_suffix(name);
    format!("{API_REPOSITORIES_PATH}/{scope}/{owner}/{visibility}/{base}")
}

/// Formats the HTTP API path for `GetTree`:
/// `/api/v1/repositories/<scope>/<owner>/<visibility>/<name>/tree`
#[must_use]
pub fn format_tree_api_path(scope: &str, owner: &str, visibility: &str, name: &str) -> String {
    let repo_path = format_repository_api_path(scope, owner, visibility, name);
    format!("{repo_path}/tree")
}

/// Formats the HTTP API path for `GetBlob`:
/// `/api/v1/repositories/<scope>/<owner>/<visibility>/<name>/blob`
#[must_use]
pub fn format_blob_api_path(scope: &str, owner: &str, visibility: &str, name: &str) -> String {
    let repo_path = format_repository_api_path(scope, owner, visibility, name);
    format!("{repo_path}/blob")
}

/// Formats the HTTP API path for `ListCommits`:
/// `/api/v1/repositories/<scope>/<owner>/<visibility>/<name>/commits`
#[must_use]
pub fn format_commits_api_path(scope: &str, owner: &str, visibility: &str, name: &str) -> String {
    let repo_path = format_repository_api_path(scope, owner, visibility, name);
    format!("{repo_path}/commits")
}

/// Formats the HTTP API path for `GetCommit`:
/// `/api/v1/repositories/<scope>/<owner>/<visibility>/<name>/commit`
#[must_use]
pub fn format_commit_api_path(scope: &str, owner: &str, visibility: &str, name: &str) -> String {
    let repo_path = format_repository_api_path(scope, owner, visibility, name);
    format!("{repo_path}/commit")
}

/// Formats the raw SSH URL (without username):
/// `ssh://<host>/<scope>/<owner>/<visibility>/<name>.git`
#[inline]
#[must_use]
pub fn format_ssh_url(
    ssh_host: &str,
    scope: &str,
    owner: &str,
    visibility: &str,
    name: &str,
) -> String {
    format_authenticated_ssh_url(ssh_host, None, scope, owner, visibility, name)
}

/// Formats an SSH URL including `<user>@` when `authenticated_user` is provided and non-empty:
/// - Anonymous: `ssh://<host>/<scope>/<owner>/<visibility>/<name>.git`
/// - Authenticated: `ssh://<user>@<host>/<scope>/<owner>/<visibility>/<name>.git`
#[must_use]
pub fn format_authenticated_ssh_url(
    ssh_host: &str,
    authenticated_user: Option<&str>,
    scope: &str,
    owner: &str,
    visibility: &str,
    name: &str,
) -> String {
    let host = normalize_ssh_host(ssh_host);
    let path = format_canonical_path(scope, owner, visibility, name);
    match authenticated_user.map(str::trim).filter(|u| !u.is_empty()) {
        Some(user) => format!("ssh://{user}@{host}{path}"),
        None => format!("ssh://{host}{path}"),
    }
}

/// Formats the ready-to-run `git clone` command:
/// - Anonymous: `git clone ssh://<host>/<scope>/<owner>/<visibility>/<name>.git`
/// - Authenticated: `git clone ssh://<user>@<host>/<scope>/<owner>/<visibility>/<name>.git`
#[must_use]
pub fn format_clone_command(
    ssh_host: &str,
    authenticated_user: Option<&str>,
    scope: &str,
    owner: &str,
    visibility: &str,
    name: &str,
) -> String {
    let url =
        format_authenticated_ssh_url(ssh_host, authenticated_user, scope, owner, visibility, name);
    format!("git clone {url}")
}


/// Formats the canonical token payload `"ro-git:v1:<user>:<exp_unix>"` if `username`
/// is a valid identifier (`^[a-zA-Z0-9_-]+$`).
#[must_use]
pub fn format_token_payload(username: &str, exp_unix_secs: u64) -> Option<String> {
    if !is_valid_identifier(username) {
        return None;
    }
    Some(format!("{TOKEN_VERSION_PREFIX}:{username}:{exp_unix_secs}"))
}

/// Parses a canonical token payload `"ro-git:v1:<user>:<exp_unix>"` into `(username, exp_unix_secs)`.
pub fn parse_token_payload(payload: &str) -> Result<(&str, u64), TokenError> {
    let rest = payload
        .strip_prefix(TOKEN_VERSION_PREFIX)
        .ok_or(TokenError::InvalidVersionPrefix)?;
    let rest = rest
        .strip_prefix(':')
        .ok_or(TokenError::InvalidPayloadFormat)?;
    let (username, exp_str) = rest
        .split_once(':')
        .ok_or(TokenError::InvalidPayloadFormat)?;
    if exp_str.contains(':') {
        return Err(TokenError::InvalidPayloadFormat);
    }
    if !is_valid_identifier(username) {
        return Err(TokenError::InvalidUsername);
    }
    if exp_str.is_empty() || !exp_str.bytes().all(|b| b.is_ascii_digit()) {
        return Err(TokenError::InvalidExpiration);
    }
    let exp_unix_secs = exp_str
        .parse::<u64>()
        .map_err(|_| TokenError::InvalidExpiration)?;
    Ok((username, exp_unix_secs))
}

/// Formats the local `ssh-keygen -Y sign` command for signing a stateless token payload:
/// `printf 'ro-git:v1:<user>:<exp_unix>' | ssh-keygen -Y sign -f ~/.ssh/id_ed25519 -n ro-git`
#[must_use]
pub fn format_ssh_keygen_sign_command(username: &str, exp_unix_secs: u64) -> Option<String> {
    let payload = format_token_payload(username, exp_unix_secs)?;
    Some(format!(
        "printf '{payload}' | ssh-keygen -Y sign -f ~/.ssh/id_ed25519 -n {SSH_SIG_NAMESPACE}"
    ))
}

/// Validates and trims an OpenSSH `SSHSIG` PEM block (`-----BEGIN SSH SIGNATURE-----` ... `-----END SSH SIGNATURE-----`).
fn validate_and_trim_sshsig_pem(sshsig_pem: &str) -> Result<&str, TokenError> {
    let trimmed = sshsig_pem.trim();
    let inner = trimmed
        .strip_prefix(SSH_SIG_PEM_BEGIN)
        .and_then(|s| s.strip_suffix(SSH_SIG_PEM_END))
        .ok_or(TokenError::InvalidSignaturePem)?;
    if inner.trim().is_empty() {
        return Err(TokenError::InvalidSignaturePem);
    }
    Ok(trimmed)
}

/// Encodes `input` as URL-safe Base64 without `=` padding (RFC 4648 §5).
#[must_use]
pub fn base64url_encode(input: &[u8]) -> String {
    let mut out = Vec::with_capacity((input.len() * 4).div_ceil(3));
    let (chunks, rem) = input.as_chunks::<3>();
    for &[b0, b1, b2] in chunks {
        out.push(BASE64URL_ALPHABET[(b0 >> 2) as usize]);
        out.push(BASE64URL_ALPHABET[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize]);
        out.push(BASE64URL_ALPHABET[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize]);
        out.push(BASE64URL_ALPHABET[(b2 & 0x3f) as usize]);
    }
    if rem.len() == 1 {
        let b0 = rem[0];
        out.push(BASE64URL_ALPHABET[(b0 >> 2) as usize]);
        out.push(BASE64URL_ALPHABET[((b0 & 0x03) << 4) as usize]);
    } else if rem.len() == 2 {
        let b0 = rem[0];
        let b1 = rem[1];
        out.push(BASE64URL_ALPHABET[(b0 >> 2) as usize]);
        out.push(BASE64URL_ALPHABET[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize]);
        out.push(BASE64URL_ALPHABET[((b1 & 0x0f) << 2) as usize]);
    }
    String::from_utf8(out).expect("base64url alphabet is valid ASCII")
}

#[inline]
const fn decode_base64url_byte(b: u8) -> Option<u8> {
    match b {
        b'A'..=b'Z' => Some(b - b'A'),
        b'a'..=b'z' => Some(b - b'a' + 26),
        b'0'..=b'9' => Some(b - b'0' + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}

/// Decodes URL-safe Base64 (accepting both unpadded and `=`-padded input).
pub fn base64url_decode(input: &str) -> Result<Vec<u8>, TokenError> {
    let bytes = input.as_bytes();
    let unpadded = if let Some(eq_pos) = bytes.iter().position(|&b| b == b'=') {
        let pad_len = bytes.len() - eq_pos;
        if !bytes.len().is_multiple_of(4)
            || pad_len > 2
            || !bytes[eq_pos..].iter().all(|&b| b == b'=')
        {
            return Err(TokenError::InvalidBase64);
        }
        &bytes[..eq_pos]
    } else {
        bytes
    };

    if unpadded.len() % 4 == 1 {
        return Err(TokenError::InvalidBase64);
    }

    let mut out = Vec::with_capacity((unpadded.len() * 3) / 4);
    let (chunks, rem) = unpadded.as_chunks::<4>();
    for &[c0, c1, c2, c3] in chunks {
        let v0 = decode_base64url_byte(c0).ok_or(TokenError::InvalidBase64)?;
        let v1 = decode_base64url_byte(c1).ok_or(TokenError::InvalidBase64)?;
        let v2 = decode_base64url_byte(c2).ok_or(TokenError::InvalidBase64)?;
        let v3 = decode_base64url_byte(c3).ok_or(TokenError::InvalidBase64)?;
        out.push((v0 << 2) | (v1 >> 4));
        out.push((v1 << 4) | (v2 >> 2));
        out.push((v2 << 6) | v3);
    }

    if rem.len() == 2 {
        let v0 = decode_base64url_byte(rem[0]).ok_or(TokenError::InvalidBase64)?;
        let v1 = decode_base64url_byte(rem[1]).ok_or(TokenError::InvalidBase64)?;
        if (v1 & 0x0f) != 0 {
            return Err(TokenError::InvalidBase64);
        }
        out.push((v0 << 2) | (v1 >> 4));
    } else if rem.len() == 3 {
        let v0 = decode_base64url_byte(rem[0]).ok_or(TokenError::InvalidBase64)?;
        let v1 = decode_base64url_byte(rem[1]).ok_or(TokenError::InvalidBase64)?;
        let v2 = decode_base64url_byte(rem[2]).ok_or(TokenError::InvalidBase64)?;
        if (v2 & 0x03) != 0 {
            return Err(TokenError::InvalidBase64);
        }
        out.push((v0 << 2) | (v1 >> 4));
        out.push((v1 << 4) | (v2 >> 2));
    }

    Ok(out)
}

/// Encodes a stateless bearer token `<base64url(payload)>.<base64url(sshsig_pem)>`
/// after validating the payload format and `SSHSIG` PEM boundaries.
pub fn encode_bearer_token(payload: &str, sshsig_pem: &str) -> Result<String, TokenError> {
    let _ = parse_token_payload(payload)?;
    let trimmed_pem = validate_and_trim_sshsig_pem(sshsig_pem)?;
    let payload_b64 = base64url_encode(payload.as_bytes());
    let sig_b64 = base64url_encode(trimmed_pem.as_bytes());
    Ok(format!("{payload_b64}.{sig_b64}"))
}

/// Decodes a `<base64url(payload)>.<base64url(sshsig_pem)>` bearer token
/// (stripping an optional leading `"Bearer "` prefix).
pub fn decode_bearer_token(token: &str) -> Result<DecodedToken, TokenError> {
    let trimmed = token.trim();
    let raw = if trimmed.len() >= 7
        && trimmed.as_bytes()[..6].eq_ignore_ascii_case(b"bearer")
        && trimmed.as_bytes()[6].is_ascii_whitespace()
    {
        trimmed[7..].trim()
    } else {
        trimmed
    };

    if raw.is_empty() {
        return Err(TokenError::MalformedToken);
    }

    let (payload_b64, sig_b64) = raw.split_once('.').ok_or(TokenError::MalformedToken)?;
    if payload_b64.is_empty() || sig_b64.is_empty() || sig_b64.contains('.') {
        return Err(TokenError::MalformedToken);
    }

    let payload_bytes = base64url_decode(payload_b64)?;
    let sig_bytes = base64url_decode(sig_b64)?;

    let payload = String::from_utf8(payload_bytes).map_err(|_| TokenError::InvalidUtf8)?;
    let sig_raw = String::from_utf8(sig_bytes).map_err(|_| TokenError::InvalidUtf8)?;
    let sshsig_pem = validate_and_trim_sshsig_pem(&sig_raw)?.to_owned();

    let (username, exp_unix_secs) = parse_token_payload(&payload)?;
    Ok(DecodedToken {
        username: username.to_owned(),
        payload,
        sshsig_pem,
        exp_unix_secs,
    })
}

/// Validates token claims (`username` identifier syntax, expiration in the future,
/// and remaining lifetime within `max_ttl_secs`).
pub fn validate_token_claims(
    username: &str,
    exp_unix_secs: u64,
    now_unix_secs: u64,
    max_ttl_secs: u64,
) -> Result<(), TokenError> {
    if !is_valid_identifier(username) {
        return Err(TokenError::InvalidUsername);
    }
    if exp_unix_secs <= now_unix_secs {
        return Err(TokenError::TokenExpired);
    }
    if exp_unix_secs.saturating_sub(now_unix_secs) > max_ttl_secs {
        return Err(TokenError::TokenTtlExceeded);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grpc::ro_git::v1::git_service::{GitService, GitServiceServer};
    use crate::ro_git::v1::{
        worker_request, worker_response, GetAuthStatusRequestView, GetAuthStatusResponseBuilder,
        GetAuthStatusResponseView, GetBlobRequestBuilder, GetBlobRequestView,
        GetBlobResponseBuilder, GetBlobResponseView, GetCommitRequestBuilder, GetCommitRequestView,
        GetCommitResponseBuilder, GetCommitResponseView, GetRepositoryRequestBuilder,
        GetRepositoryRequestView, GetRepositoryResponseBuilder, GetRepositoryResponseView,
        GetTreeRequestBuilder, GetTreeRequestView, GetTreeResponseBuilder, GetTreeResponseView,
        ListCommitsRequestBuilder, ListCommitsRequestView, ListCommitsResponseBuilder,
        ListCommitsResponseView, ListRepositoriesRequestBuilder, ListRepositoriesRequestView,
        ListRepositoriesResponseBuilder, ListRepositoriesResponseView, WorkerRequestBuilder,
        WorkerRequestView, WorkerResponseBuilder, WorkerResponseView,
    };
    use alloc::vec::Vec;
    use roto::runtime::BackwardWriter;
    use roto_grpc::http::{HttpMethod, HttpRequest};
    use roto_grpc::{GrpcStatus, RpcContext, RpcMetadata};

    const SAMPLE_OID_1: &str = "0123456789abcdef0123456789abcdef01234567";
    const SAMPLE_OID_2: &str = "89abcdef0123456789abcdef0123456789abcdef";
    const SAMPLE_OID_3: &str = "fedcba9876543210fedcba9876543210fedcba98";

    #[test]
    fn formats_canonical_paths_ssh_urls_and_clone_commands() {
        assert_eq!(normalize_ssh_host(""), "localhost");
        assert_eq!(normalize_ssh_host("   "), "localhost");
        assert_eq!(normalize_ssh_host("ssh:///"), "localhost");
        assert_eq!(
            normalize_ssh_host("ssh://git.example.com:2222/"),
            "git.example.com:2222"
        );

        assert_eq!(
            format_canonical_path("users", "alice", "public", "notes"),
            "/users/alice/public/notes.git"
        );
        assert_eq!(
            format_canonical_path("teams", "core", "private", "infra.git"),
            "/teams/core/private/infra.git"
        );

        assert_eq!(
            format_repository_api_path("users", "alice", "public", "notes.git"),
            "/api/v1/repositories/users/alice/public/notes"
        );
        assert_eq!(
            format_tree_api_path("users", "alice", "public", "notes"),
            "/api/v1/repositories/users/alice/public/notes/tree"
        );
        assert_eq!(
            format_blob_api_path("users", "alice", "public", "notes"),
            "/api/v1/repositories/users/alice/public/notes/blob"
        );
        assert_eq!(
            format_commits_api_path("teams", "core", "private", "infra.git"),
            "/api/v1/repositories/teams/core/private/infra/commits"
        );
        assert_eq!(
            format_commit_api_path("teams", "core", "private", "infra"),
            "/api/v1/repositories/teams/core/private/infra/commit"
        );

        assert_eq!(
            format_ssh_url("git.example.com", "users", "alice", "public", "notes.git"),
            "ssh://git.example.com/users/alice/public/notes.git"
        );
        assert_eq!(
            format_ssh_url("ssh://localhost:2222/", "teams", "core", "private", "infra"),
            "ssh://localhost:2222/teams/core/private/infra.git"
        );
        assert_eq!(
            format_ssh_url("", "users", "alice", "public", "notes"),
            "ssh://localhost/users/alice/public/notes.git"
        );

        assert_eq!(
            format_clone_command("localhost", None, "users", "alice", "public", "notes"),
            "git clone ssh://localhost/users/alice/public/notes.git"
        );
        assert_eq!(
            format_clone_command("localhost", Some(""), "users", "alice", "public", "notes"),
            "git clone ssh://localhost/users/alice/public/notes.git"
        );
        assert_eq!(
            format_clone_command(
                "git.example.com:2222",
                Some("alice"),
                "users",
                "alice",
                "private",
                "secret.git"
            ),
            "git clone ssh://alice@git.example.com:2222/users/alice/private/secret.git"
        );
        assert_eq!(
            format_clone_command(
                "git.example.com",
                Some("bob"),
                "teams",
                "platform",
                "private",
                "deploy"
            ),
            "git clone ssh://bob@git.example.com/teams/platform/private/deploy.git"
        );
    }

    #[test]
    fn validates_scopes_visibilities_identifiers_and_git_helpers() {
        assert!(is_valid_scope("users"));
        assert!(is_valid_scope("teams"));
        assert!(!is_valid_scope("orgs"));
        assert!(!is_valid_scope(""));

        assert!(is_valid_visibility("public"));
        assert!(is_valid_visibility("private"));
        assert!(!is_valid_visibility("internal"));

        assert!(is_valid_identifier("alice_01-dev"));
        assert!(!is_valid_identifier(""));
        assert!(!is_valid_identifier("../etc"));
        assert!(!is_valid_identifier("repo.git"));

        assert!(is_valid_tree_kind(TREE_KIND_FILE));
        assert!(is_valid_tree_kind(TREE_KIND_DIR));
        assert!(is_valid_tree_kind(TREE_KIND_SYMLINK));
        assert!(is_valid_tree_kind(TREE_KIND_SUBMODULE));
        assert!(!is_valid_tree_kind("unknown"));

        assert_eq!(tree_kind_from_mode("100644"), Some(TREE_KIND_FILE));
        assert_eq!(tree_kind_from_mode("100755"), Some(TREE_KIND_FILE));
        assert_eq!(tree_kind_from_mode("040000"), Some(TREE_KIND_DIR));
        assert_eq!(tree_kind_from_mode("40000"), Some(TREE_KIND_DIR));
        assert_eq!(tree_kind_from_mode("120000"), Some(TREE_KIND_SYMLINK));
        assert_eq!(tree_kind_from_mode("160000"), Some(TREE_KIND_SUBMODULE));
        assert_eq!(tree_kind_from_mode("999999"), None);

        assert!(is_valid_diff_status(DIFF_STATUS_ADDED));
        assert!(is_valid_diff_status(DIFF_STATUS_MODIFIED));
        assert!(is_valid_diff_status(DIFF_STATUS_DELETED));
        assert!(is_valid_diff_status(DIFF_STATUS_RENAMED));
        assert!(is_valid_diff_status(DIFF_STATUS_COPIED));
        assert!(is_valid_diff_status(DIFF_STATUS_TYPECHANGE));
        assert!(!is_valid_diff_status("unknown"));

        assert!(is_valid_oid(SAMPLE_OID_1));
        assert!(!is_valid_oid("012345"));
        assert!(!is_valid_oid("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"));

        assert_eq!(normalize_revision(""), "HEAD");
        assert_eq!(normalize_revision("   "), "HEAD");
        assert_eq!(normalize_revision(" main "), "main");

        assert!(is_valid_revision("HEAD"));
        assert!(is_valid_revision("main"));
        assert!(is_valid_revision("feature/issue-006"));
        assert!(is_valid_revision("v1.0.0"));
        assert!(is_valid_revision(SAMPLE_OID_1));
        assert!(!is_valid_revision(""));
        assert!(!is_valid_revision("-n"));
        assert!(!is_valid_revision("/main"));
        assert!(!is_valid_revision("main/"));
        assert!(!is_valid_revision("@"));
        assert!(!is_valid_revision(".hidden"));
        assert!(!is_valid_revision("refs/heads/.hidden"));
        assert!(!is_valid_revision("main."));
        assert!(!is_valid_revision("feature/branch./sub"));
        assert!(!is_valid_revision("main.lock"));
        assert!(!is_valid_revision("feature/branch.lock/sub"));
        assert!(!is_valid_revision("a..b"));
        assert!(!is_valid_revision("a//b"));
        assert!(!is_valid_revision("HEAD@{1}"));
        assert!(!is_valid_revision("HEAD~1"));
        assert!(!is_valid_revision("HEAD^"));
        assert!(!is_valid_revision("a:b"));

        assert_eq!(normalize_repo_path(""), Some(String::new()));
        assert_eq!(normalize_repo_path("/"), Some(String::new()));
        assert_eq!(
            normalize_repo_path(" /crates//ro-git-ui/src/lib.rs/ "),
            Some(String::from("crates/ro-git-ui/src/lib.rs"))
        );
        assert_eq!(normalize_repo_path("../secret"), None);
        assert_eq!(normalize_repo_path("crates/../secret"), None);
        assert_eq!(normalize_repo_path("./README.md"), None);
        assert_eq!(normalize_repo_path("crates\\lib.rs"), None);
        assert_eq!(normalize_repo_path("crates/\0/lib.rs"), None);
    }

    #[test]
    fn roundtrips_get_auth_status_response() {
        let mut buf = [0u8; 256];
        let mut builder = GetAuthStatusResponseBuilder::new(&mut buf);
        builder
            .write_ssh_host("git.example.com:2222")
            .write_username("charles")
            .write_authenticated(true);
        let bytes = builder.finish().expect("encode GetAuthStatusResponse");

        let view = GetAuthStatusResponseView::from_bytes(bytes).expect("decode view");
        assert!(view.authenticated().expect("authenticated"));
        assert_eq!(view.username().expect("username"), "charles");
        assert_eq!(view.ssh_host().expect("ssh_host"), "git.example.com:2222");
    }

    #[test]
    fn roundtrips_list_repositories_request_and_response() {
        let mut req_buf = [0u8; 256];
        let mut req_builder = ListRepositoriesRequestBuilder::new(&mut req_buf);
        req_builder
            .write_query("engine")
            .write_visibility("private")
            .write_owner("core")
            .write_scope("teams");
        let req_bytes = req_builder.finish().expect("encode request");

        let req_view = ListRepositoriesRequestView::from_bytes(req_bytes).expect("decode request");
        assert_eq!(req_view.scope().expect("scope"), "teams");
        assert_eq!(req_view.owner().expect("owner"), "core");
        assert_eq!(req_view.visibility().expect("visibility"), "private");
        assert_eq!(req_view.query().expect("query"), "engine");

        let fixtures = [
            ("users", "alice", "public", "dotfiles"),
            ("teams", "core", "private", "ro-git"),
        ];

        let mut resp_buf = [0u8; 1024];
        let mut resp_builder = ListRepositoriesResponseBuilder::new(&mut resp_buf);
        resp_builder
            .write_ssh_host("git.local")
            .write_authenticated_user("alice");

        for &(scope, owner, vis, name) in fixtures.iter().rev() {
            let canonical = format_canonical_path(scope, owner, vis, name);
            let ssh_url = format_ssh_url("git.local", scope, owner, vis, name);
            let clone_cmd =
                format_clone_command("git.local", Some("alice"), scope, owner, vis, name);
            resp_builder.write_repositories(|repo| {
                repo.write_clone_command(&clone_cmd)
                    .write_ssh_url(&ssh_url)
                    .write_canonical_path(&canonical)
                    .write_name(name)
                    .write_visibility(vis)
                    .write_owner(owner)
                    .write_scope(scope);
            });
            resp_builder.check().expect("buffer capacity");
        }

        let resp_bytes = resp_builder.finish().expect("encode response");
        let resp_view =
            ListRepositoriesResponseView::from_bytes(resp_bytes).expect("decode response");
        assert_eq!(resp_view.authenticated_user().expect("user"), "alice");
        assert_eq!(resp_view.ssh_host().expect("host"), "git.local");

        let decoded: Vec<_> = resp_view
            .repositories()
            .map(|r| {
                let v = r.expect("valid RepositoryInfoView");
                (
                    v.scope().unwrap(),
                    v.owner().unwrap(),
                    v.visibility().unwrap(),
                    v.name().unwrap(),
                    v.canonical_path().unwrap(),
                    v.ssh_url().unwrap(),
                    v.clone_command().unwrap(),
                )
            })
            .collect();

        assert_eq!(
            decoded,
            alloc::vec![
                (
                    "users",
                    "alice",
                    "public",
                    "dotfiles",
                    "/users/alice/public/dotfiles.git",
                    "ssh://git.local/users/alice/public/dotfiles.git",
                    "git clone ssh://alice@git.local/users/alice/public/dotfiles.git",
                ),
                (
                    "teams",
                    "core",
                    "private",
                    "ro-git",
                    "/teams/core/private/ro-git.git",
                    "ssh://git.local/teams/core/private/ro-git.git",
                    "git clone ssh://alice@git.local/teams/core/private/ro-git.git",
                ),
            ]
        );
    }

    #[test]
    fn roundtrips_get_repository_and_get_tree_messages() {
        let mut req_buf = [0u8; 256];
        let mut req_builder = GetRepositoryRequestBuilder::new(&mut req_buf);
        req_builder
            .write_revision("main")
            .write_name("ro-git")
            .write_visibility("public")
            .write_owner("alice")
            .write_scope("users");
        let req_bytes = req_builder.finish().expect("encode GetRepositoryRequest");
        let req_view =
            GetRepositoryRequestView::from_bytes(req_bytes).expect("decode GetRepositoryRequest");
        assert_eq!(req_view.scope().unwrap(), "users");
        assert_eq!(req_view.owner().unwrap(), "alice");
        assert_eq!(req_view.visibility().unwrap(), "public");
        assert_eq!(req_view.name().unwrap(), "ro-git");
        assert_eq!(req_view.revision().unwrap(), "main");

        let branches = [
            ("dev", "refs/heads/dev", SAMPLE_OID_2),
            ("main", "refs/heads/main", SAMPLE_OID_1),
        ];
        let tags = [("v1.0.0", "refs/tags/v1.0.0", SAMPLE_OID_1)];
        let entries = [
            ("040000", TREE_KIND_DIR, "crates", "crates", SAMPLE_OID_2, 0u64),
            (
                "100644",
                TREE_KIND_FILE,
                "README.md",
                "README.md",
                SAMPLE_OID_3,
                1420u64,
            ),
        ];

        let mut resp_buf = [0u8; 2048];
        let mut resp_builder = GetRepositoryResponseBuilder::new(&mut resp_buf);
        for &(mode, kind, name, path, oid, size) in entries.iter().rev() {
            resp_builder.write_entries(|e| {
                e.write_size(size)
                    .write_oid(oid)
                    .write_path(path)
                    .write_name(name)
                    .write_kind(kind)
                    .write_mode(mode);
            });
            resp_builder.check().expect("entries buffer capacity");
        }
        for &(name, full_name, oid) in tags.iter().rev() {
            resp_builder.write_tags(|t| {
                t.write_oid(oid)
                    .write_full_name(full_name)
                    .write_name(name);
            });
            resp_builder.check().expect("tags buffer capacity");
        }
        for &(name, full_name, oid) in branches.iter().rev() {
            resp_builder.write_branches(|b| {
                b.write_oid(oid)
                    .write_full_name(full_name)
                    .write_name(name);
            });
            resp_builder.check().expect("branches buffer capacity");
        }
        resp_builder
            .write_resolved_revision("main")
            .write_head_oid(SAMPLE_OID_1)
            .write_head_ref("main")
            .write_repository(|repo| {
                repo.write_clone_command("git clone ssh://git.local/users/alice/public/ro-git.git")
                    .write_ssh_url("ssh://git.local/users/alice/public/ro-git.git")
                    .write_canonical_path("/users/alice/public/ro-git.git")
                    .write_name("ro-git")
                    .write_visibility("public")
                    .write_owner("alice")
                    .write_scope("users");
            });

        let resp_bytes = resp_builder.finish().expect("encode GetRepositoryResponse");
        let resp_view = GetRepositoryResponseView::from_bytes(resp_bytes)
            .expect("decode GetRepositoryResponse");
        let repo_view = resp_view
            .repository()
            .expect("decode repo")
            .expect("repo present");
        assert_eq!(repo_view.name().unwrap(), "ro-git");
        assert_eq!(resp_view.head_ref().unwrap(), "main");
        assert_eq!(resp_view.head_oid().unwrap(), SAMPLE_OID_1);
        assert_eq!(resp_view.resolved_revision().unwrap(), "main");

        let decoded_branches: Vec<_> = resp_view
            .branches()
            .map(|b| {
                let v = b.unwrap();
                (
                    v.name().unwrap(),
                    v.full_name().unwrap(),
                    v.oid().unwrap(),
                )
            })
            .collect();
        assert_eq!(decoded_branches, branches);

        let decoded_tags: Vec<_> = resp_view
            .tags()
            .map(|t| {
                let v = t.unwrap();
                (
                    v.name().unwrap(),
                    v.full_name().unwrap(),
                    v.oid().unwrap(),
                )
            })
            .collect();
        assert_eq!(decoded_tags, tags);

        let decoded_entries: Vec<_> = resp_view
            .entries()
            .map(|e| {
                let v = e.unwrap();
                (
                    v.mode().unwrap(),
                    v.kind().unwrap(),
                    v.name().unwrap(),
                    v.path().unwrap(),
                    v.oid().unwrap(),
                    v.size().unwrap(),
                )
            })
            .collect();
        assert_eq!(decoded_entries, entries);

        // GetTreeRequest & GetTreeResponse roundtrip
        let mut tree_req_buf = [0u8; 256];
        let mut tree_req_builder = GetTreeRequestBuilder::new(&mut tree_req_buf);
        tree_req_builder
            .write_path("crates/ro-git-proto")
            .write_revision("v1.0.0")
            .write_name("ro-git")
            .write_visibility("public")
            .write_owner("alice")
            .write_scope("users");
        let tree_req_bytes = tree_req_builder.finish().expect("encode GetTreeRequest");
        let tree_req_view =
            GetTreeRequestView::from_bytes(tree_req_bytes).expect("decode GetTreeRequest");
        assert_eq!(tree_req_view.path().unwrap(), "crates/ro-git-proto");
        assert_eq!(tree_req_view.revision().unwrap(), "v1.0.0");

        let mut tree_resp_buf = [0u8; 512];
        let mut tree_resp_builder = GetTreeResponseBuilder::new(&mut tree_resp_buf);
        tree_resp_builder
            .write_entries(|e| {
                e.write_size(512)
                    .write_oid(SAMPLE_OID_3)
                    .write_path("crates/ro-git-proto/Cargo.toml")
                    .write_name("Cargo.toml")
                    .write_kind(TREE_KIND_FILE)
                    .write_mode("100644");
            })
            .write_path("crates/ro-git-proto")
            .write_tree_oid(SAMPLE_OID_2)
            .write_revision("v1.0.0");
        let tree_resp_bytes = tree_resp_builder.finish().expect("encode GetTreeResponse");
        let tree_resp_view =
            GetTreeResponseView::from_bytes(tree_resp_bytes).expect("decode GetTreeResponse");
        assert_eq!(tree_resp_view.revision().unwrap(), "v1.0.0");
        assert_eq!(tree_resp_view.tree_oid().unwrap(), SAMPLE_OID_2);
        assert_eq!(tree_resp_view.path().unwrap(), "crates/ro-git-proto");
        assert_eq!(tree_resp_view.entries().count(), 1);
    }

    #[test]
    fn roundtrips_get_blob_list_commits_and_get_commit_messages() {
        // 1. GetBlobRequest & GetBlobResponse
        let mut blob_req_buf = [0u8; 256];
        let mut blob_req_builder = GetBlobRequestBuilder::new(&mut blob_req_buf);
        blob_req_builder
            .write_path("README.md")
            .write_revision("HEAD")
            .write_name("ro-git")
            .write_visibility("public")
            .write_owner("alice")
            .write_scope("users");
        let blob_req_bytes = blob_req_builder.finish().expect("encode GetBlobRequest");
        let blob_req_view =
            GetBlobRequestView::from_bytes(blob_req_bytes).expect("decode GetBlobRequest");
        assert_eq!(blob_req_view.path().unwrap(), "README.md");
        assert_eq!(blob_req_view.revision().unwrap(), "HEAD");

        let raw_content = b"# ro-git\nPure read-only Git server.\n";
        let mut blob_resp_buf = [0u8; 512];
        let mut blob_resp_builder = GetBlobResponseBuilder::new(&mut blob_resp_buf);
        blob_resp_builder
            .write_content(raw_content)
            .write_truncated(false)
            .write_is_binary(false)
            .write_size(raw_content.len() as u64)
            .write_oid(SAMPLE_OID_3)
            .write_path("README.md")
            .write_revision("HEAD");
        let blob_resp_bytes = blob_resp_builder.finish().expect("encode GetBlobResponse");
        let blob_resp_view =
            GetBlobResponseView::from_bytes(blob_resp_bytes).expect("decode GetBlobResponse");
        assert_eq!(blob_resp_view.revision().unwrap(), "HEAD");
        assert_eq!(blob_resp_view.path().unwrap(), "README.md");
        assert_eq!(blob_resp_view.oid().unwrap(), SAMPLE_OID_3);
        assert_eq!(blob_resp_view.size().unwrap(), raw_content.len() as u64);
        assert!(!blob_resp_view.is_binary().unwrap());
        assert!(!blob_resp_view.truncated().unwrap());
        assert_eq!(blob_resp_view.content().unwrap(), raw_content);

        // 2. ListCommitsRequest & ListCommitsResponse
        let mut commits_req_buf = [0u8; 256];
        let mut commits_req_builder = ListCommitsRequestBuilder::new(&mut commits_req_buf);
        commits_req_builder
            .write_offset(10)
            .write_limit(25)
            .write_path("crates/ro-git-proto")
            .write_revision("main")
            .write_name("ro-git")
            .write_visibility("public")
            .write_owner("alice")
            .write_scope("users");
        let commits_req_bytes = commits_req_builder
            .finish()
            .expect("encode ListCommitsRequest");
        let commits_req_view =
            ListCommitsRequestView::from_bytes(commits_req_bytes).expect("decode ListCommitsRequest");
        assert_eq!(commits_req_view.revision().unwrap(), "main");
        assert_eq!(commits_req_view.path().unwrap(), "crates/ro-git-proto");
        assert_eq!(commits_req_view.limit().unwrap(), 25);
        assert_eq!(commits_req_view.offset().unwrap(), 10);

        let parents = [SAMPLE_OID_2, SAMPLE_OID_3];
        let mut commits_resp_buf = [0u8; 1024];
        let mut commits_resp_builder = ListCommitsResponseBuilder::new(&mut commits_resp_buf);
        commits_resp_builder
            .write_has_more(true)
            .write_commits(|c| {
                c.write_message("Initial commit\n\nBody text.")
                    .write_subject("Initial commit")
                    .write_committer_time_secs(1_700_000_100)
                    .write_committer_email("alice@example.com")
                    .write_committer_name("Alice")
                    .write_author_time_secs(1_700_000_000)
                    .write_author_email("alice@example.com")
                    .write_author_name("Alice");
                for &parent in parents.iter().rev() {
                    c.write_parent_oids(parent);
                    c.check().expect("parent_oids capacity");
                }
                c.write_oid(SAMPLE_OID_1);
            })
            .write_revision("main");
        let commits_resp_bytes = commits_resp_builder
            .finish()
            .expect("encode ListCommitsResponse");
        let commits_resp_view = ListCommitsResponseView::from_bytes(commits_resp_bytes)
            .expect("decode ListCommitsResponse");
        assert_eq!(commits_resp_view.revision().unwrap(), "main");
        assert!(commits_resp_view.has_more().unwrap());
        let commit_view = commits_resp_view
            .commits()
            .next()
            .expect("one commit")
            .expect("valid CommitInfoView");
        assert_eq!(commit_view.oid().unwrap(), SAMPLE_OID_1);
        let decoded_parents: Vec<_> = commit_view.parent_oids().map(|p| p.unwrap()).collect();
        assert_eq!(decoded_parents, parents);
        assert_eq!(commit_view.author_name().unwrap(), "Alice");
        assert_eq!(commit_view.author_email().unwrap(), "alice@example.com");
        assert_eq!(commit_view.author_time_secs().unwrap(), 1_700_000_000);
        assert_eq!(commit_view.committer_name().unwrap(), "Alice");
        assert_eq!(commit_view.committer_email().unwrap(), "alice@example.com");
        assert_eq!(commit_view.committer_time_secs().unwrap(), 1_700_000_100);
        assert_eq!(commit_view.subject().unwrap(), "Initial commit");
        assert_eq!(
            commit_view.message().unwrap(),
            "Initial commit\n\nBody text."
        );

        // 3. GetCommitRequest & GetCommitResponse
        let mut commit_req_buf = [0u8; 256];
        let mut commit_req_builder = GetCommitRequestBuilder::new(&mut commit_req_buf);
        commit_req_builder
            .write_revision(SAMPLE_OID_1)
            .write_name("ro-git")
            .write_visibility("public")
            .write_owner("alice")
            .write_scope("users");
        let commit_req_bytes = commit_req_builder.finish().expect("encode GetCommitRequest");
        let commit_req_view =
            GetCommitRequestView::from_bytes(commit_req_bytes).expect("decode GetCommitRequest");
        assert_eq!(commit_req_view.revision().unwrap(), SAMPLE_OID_1);

        let mut commit_resp_buf = [0u8; 1024];
        let mut commit_resp_builder = GetCommitResponseBuilder::new(&mut commit_resp_buf);
        commit_resp_builder
            .write_patch("@@ -1 +1,2 @@\n+hello\n")
            .write_total_deletions(1)
            .write_total_additions(5)
            .write_files(|f| {
                f.write_patch("@@ -1 +1,2 @@\n+hello\n")
                    .write_deletions(1)
                    .write_additions(5)
                    .write_status(DIFF_STATUS_RENAMED)
                    .write_old_path("OLD_README.md")
                    .write_path("README.md");
            })
            .write_commit(|c| {
                c.write_message("Rename README")
                    .write_subject("Rename README")
                    .write_committer_time_secs(1_700_000_200)
                    .write_committer_email("alice@example.com")
                    .write_committer_name("Alice")
                    .write_author_time_secs(1_700_000_200)
                    .write_author_email("alice@example.com")
                    .write_author_name("Alice")
                    .write_parent_oids(SAMPLE_OID_2)
                    .write_oid(SAMPLE_OID_1);
            });
        let commit_resp_bytes = commit_resp_builder
            .finish()
            .expect("encode GetCommitResponse");
        let commit_resp_view =
            GetCommitResponseView::from_bytes(commit_resp_bytes).expect("decode GetCommitResponse");
        assert_eq!(commit_resp_view.total_additions().unwrap(), 5);
        assert_eq!(commit_resp_view.total_deletions().unwrap(), 1);
        assert_eq!(
            commit_resp_view.patch().unwrap(),
            "@@ -1 +1,2 @@\n+hello\n"
        );
        let diff_view = commit_resp_view
            .files()
            .next()
            .expect("one file diff")
            .expect("valid CommitFileDiffView");
        assert_eq!(diff_view.path().unwrap(), "README.md");
        assert_eq!(diff_view.old_path().unwrap(), "OLD_README.md");
        assert_eq!(diff_view.status().unwrap(), DIFF_STATUS_RENAMED);
        assert_eq!(diff_view.additions().unwrap(), 5);
        assert_eq!(diff_view.deletions().unwrap(), 1);
    }

    #[test]
    fn roundtrips_worker_ipc_envelopes() {
        let mut req_buf = [0u8; 512];
        let mut req_builder = WorkerRequestBuilder::new(&mut req_buf);
        req_builder
            .write_list_repositories(|lr| {
                lr.write_owner("alice").write_scope("users");
            })
            .write_now_unix_secs(1_700_000_000)
            .write_max_token_ttl_secs(2_592_000)
            .write_ssh_host("localhost")
            .write_root_dir("/srv/git")
            .write_token("payload.sig");

        let req_bytes = req_builder.finish().expect("encode WorkerRequest");
        let req_view = WorkerRequestView::from_bytes(req_bytes).expect("decode WorkerRequest");
        assert_eq!(req_view.token().unwrap(), "payload.sig");
        assert_eq!(req_view.root_dir().unwrap(), "/srv/git");
        assert_eq!(req_view.ssh_host().unwrap(), "localhost");
        assert_eq!(req_view.max_token_ttl_secs().unwrap(), 2_592_000);
        assert_eq!(req_view.now_unix_secs().unwrap(), 1_700_000_000);

        match req_view.command().expect("command oneof") {
            Some(worker_request::Command::ListRepositories(lr)) => {
                assert_eq!(lr.scope().unwrap(), "users");
                assert_eq!(lr.owner().unwrap(), "alice");
            }
            other => panic!("expected ListRepositories command, got {other:?}"),
        }

        // Test all 5 new WorkerRequest command variants and WorkerResponse result variants
        {
            let mut buf = [0u8; 512];
            let mut b = WorkerRequestBuilder::new(&mut buf);
            b.write_get_repository(|gr| {
                gr.write_revision("main")
                    .write_name("repo")
                    .write_visibility("public")
                    .write_owner("alice")
                    .write_scope("users");
            });
            let view = WorkerRequestView::from_bytes(b.finish().unwrap()).unwrap();
            assert!(matches!(
                view.command().unwrap(),
                Some(worker_request::Command::GetRepository(gr)) if gr.name().unwrap() == "repo"
            ));
        }
        {
            let mut buf = [0u8; 512];
            let mut b = WorkerRequestBuilder::new(&mut buf);
            b.write_get_tree(|gt| {
                gt.write_path("src")
                    .write_revision("HEAD")
                    .write_name("repo");
            });
            let view = WorkerRequestView::from_bytes(b.finish().unwrap()).unwrap();
            assert!(matches!(
                view.command().unwrap(),
                Some(worker_request::Command::GetTree(gt)) if gt.path().unwrap() == "src"
            ));
        }
        {
            let mut buf = [0u8; 512];
            let mut b = WorkerRequestBuilder::new(&mut buf);
            b.write_get_blob(|gb| {
                gb.write_path("src/lib.rs")
                    .write_revision("HEAD")
                    .write_name("repo");
            });
            let view = WorkerRequestView::from_bytes(b.finish().unwrap()).unwrap();
            assert!(matches!(
                view.command().unwrap(),
                Some(worker_request::Command::GetBlob(gb)) if gb.path().unwrap() == "src/lib.rs"
            ));
        }
        {
            let mut buf = [0u8; 512];
            let mut b = WorkerRequestBuilder::new(&mut buf);
            b.write_list_commits(|lc| {
                lc.write_limit(10).write_revision("main").write_name("repo");
            });
            let view = WorkerRequestView::from_bytes(b.finish().unwrap()).unwrap();
            assert!(matches!(
                view.command().unwrap(),
                Some(worker_request::Command::ListCommits(lc)) if lc.limit().unwrap() == 10
            ));
        }
        {
            let mut buf = [0u8; 512];
            let mut b = WorkerRequestBuilder::new(&mut buf);
            b.write_get_commit(|gc| {
                gc.write_revision(SAMPLE_OID_1).write_name("repo");
            });
            let view = WorkerRequestView::from_bytes(b.finish().unwrap()).unwrap();
            assert!(matches!(
                view.command().unwrap(),
                Some(worker_request::Command::GetCommit(gc)) if gc.revision().unwrap() == SAMPLE_OID_1
            ));
        }

        let mut resp_buf = [0u8; 512];
        let mut resp_builder = WorkerResponseBuilder::new(&mut resp_buf);
        resp_builder
            .write_auth_status(|auth| {
                auth.write_ssh_host("localhost")
                    .write_username("alice")
                    .write_authenticated(true);
            })
            .write_status_code(0);
        let resp_bytes = resp_builder.finish().expect("encode WorkerResponse");
        let resp_view = WorkerResponseView::from_bytes(resp_bytes).expect("decode WorkerResponse");
        assert_eq!(resp_view.status_code().unwrap(), 0);
        match resp_view.result().expect("result oneof") {
            Some(worker_response::Result::AuthStatus(auth)) => {
                assert!(auth.authenticated().unwrap());
                assert_eq!(auth.username().unwrap(), "alice");
            }
            other => panic!("expected AuthStatus result, got {other:?}"),
        }

        {
            let mut buf = [0u8; 512];
            let mut b = WorkerResponseBuilder::new(&mut buf);
            b.write_get_repository(|gr| {
                gr.write_head_ref("main");
            })
            .write_status_code(0);
            let view = WorkerResponseView::from_bytes(b.finish().unwrap()).unwrap();
            assert!(matches!(
                view.result().unwrap(),
                Some(worker_response::Result::GetRepository(gr)) if gr.head_ref().unwrap() == "main"
            ));
        }
        {
            let mut buf = [0u8; 512];
            let mut b = WorkerResponseBuilder::new(&mut buf);
            b.write_get_tree(|gt| {
                gt.write_tree_oid(SAMPLE_OID_2);
            })
            .write_status_code(0);
            let view = WorkerResponseView::from_bytes(b.finish().unwrap()).unwrap();
            assert!(matches!(
                view.result().unwrap(),
                Some(worker_response::Result::GetTree(gt)) if gt.tree_oid().unwrap() == SAMPLE_OID_2
            ));
        }
        {
            let mut buf = [0u8; 512];
            let mut b = WorkerResponseBuilder::new(&mut buf);
            b.write_get_blob(|gb| {
                gb.write_content(b"abc").write_size(3);
            })
            .write_status_code(0);
            let view = WorkerResponseView::from_bytes(b.finish().unwrap()).unwrap();
            assert!(matches!(
                view.result().unwrap(),
                Some(worker_response::Result::GetBlob(gb)) if gb.content().unwrap() == b"abc"
            ));
        }
        {
            let mut buf = [0u8; 512];
            let mut b = WorkerResponseBuilder::new(&mut buf);
            b.write_list_commits(|lc| {
                lc.write_has_more(false).write_revision("main");
            })
            .write_status_code(0);
            let view = WorkerResponseView::from_bytes(b.finish().unwrap()).unwrap();
            assert!(matches!(
                view.result().unwrap(),
                Some(worker_response::Result::ListCommits(lc)) if lc.revision().unwrap() == "main"
            ));
        }
        {
            let mut buf = [0u8; 512];
            let mut b = WorkerResponseBuilder::new(&mut buf);
            b.write_get_commit(|gc| {
                gc.write_total_additions(7);
            })
            .write_status_code(0);
            let view = WorkerResponseView::from_bytes(b.finish().unwrap()).unwrap();
            assert!(matches!(
                view.result().unwrap(),
                Some(worker_response::Result::GetCommit(gc)) if gc.total_additions().unwrap() == 7
            ));
        }
    }

    struct StubGitService;

    impl GitService for StubGitService {
        fn get_auth_status<'a, 'b>(
            &self,
            _meta: &mut RpcMetadata<'_>,
            _req: GetAuthStatusRequestView<'a>,
            resp: &mut GetAuthStatusResponseBuilder<'b>,
        ) -> Result<(), GrpcStatus<'static>> {
            resp.write_ssh_host("git.test")
                .write_username("tester")
                .write_authenticated(true);
            Ok(())
        }

        fn list_repositories<'a, 'b>(
            &self,
            _meta: &mut RpcMetadata<'_>,
            req: ListRepositoriesRequestView<'a>,
            resp: &mut ListRepositoriesResponseBuilder<'b>,
        ) -> Result<(), GrpcStatus<'static>> {
            let scope = req.scope().unwrap_or("users");
            let owner = req.owner().unwrap_or("tester");
            let vis = req.visibility().unwrap_or("public");
            let name = req.query().unwrap_or("sample");
            let canonical = format_canonical_path(scope, owner, vis, name);
            let ssh_url = format_ssh_url("git.test", scope, owner, vis, name);
            let clone_cmd =
                format_clone_command("git.test", Some("tester"), scope, owner, vis, name);

            resp.write_ssh_host("git.test")
                .write_authenticated_user("tester")
                .write_repositories(|repo| {
                    repo.write_clone_command(&clone_cmd)
                        .write_ssh_url(&ssh_url)
                        .write_canonical_path(&canonical)
                        .write_name(name)
                        .write_visibility(vis)
                        .write_owner(owner)
                        .write_scope(scope);
                });
            Ok(())
        }

        fn get_repository<'a, 'b>(
            &self,
            _meta: &mut RpcMetadata<'_>,
            req: GetRepositoryRequestView<'a>,
            resp: &mut GetRepositoryResponseBuilder<'b>,
        ) -> Result<(), GrpcStatus<'static>> {
            let scope = req.scope().unwrap_or("");
            let owner = req.owner().unwrap_or("");
            let vis = req.visibility().unwrap_or("");
            let name = req.name().unwrap_or("");
            let rev = normalize_revision(req.revision().unwrap_or(""));
            let canonical = format_canonical_path(scope, owner, vis, name);
            let ssh_url = format_ssh_url("git.test", scope, owner, vis, name);
            let clone_cmd = format_clone_command("git.test", None, scope, owner, vis, name);

            resp.write_entries(|e| {
                e.write_size(128)
                    .write_oid(SAMPLE_OID_3)
                    .write_path("README.md")
                    .write_name("README.md")
                    .write_kind(TREE_KIND_FILE)
                    .write_mode("100644");
            })
            .write_tags(|t| {
                t.write_oid(SAMPLE_OID_1)
                    .write_full_name("refs/tags/v1.0.0")
                    .write_name("v1.0.0");
            })
            .write_branches(|b| {
                b.write_oid(SAMPLE_OID_1)
                    .write_full_name("refs/heads/main")
                    .write_name("main");
            })
            .write_resolved_revision(rev)
            .write_head_oid(SAMPLE_OID_1)
            .write_head_ref("main")
            .write_repository(|repo| {
                repo.write_clone_command(&clone_cmd)
                    .write_ssh_url(&ssh_url)
                    .write_canonical_path(&canonical)
                    .write_name(name)
                    .write_visibility(vis)
                    .write_owner(owner)
                    .write_scope(scope);
            });
            Ok(())
        }

        fn get_tree<'a, 'b>(
            &self,
            _meta: &mut RpcMetadata<'_>,
            req: GetTreeRequestView<'a>,
            resp: &mut GetTreeResponseBuilder<'b>,
        ) -> Result<(), GrpcStatus<'static>> {
            let rev = normalize_revision(req.revision().unwrap_or(""));
            let path = req.path().unwrap_or("");
            resp.write_entries(|e| {
                e.write_size(64)
                    .write_oid(SAMPLE_OID_3)
                    .write_path(path)
                    .write_name("lib.rs")
                    .write_kind(TREE_KIND_FILE)
                    .write_mode("100644");
            })
            .write_path(path)
            .write_tree_oid(SAMPLE_OID_2)
            .write_revision(rev);
            Ok(())
        }

        fn get_blob<'a, 'b>(
            &self,
            _meta: &mut RpcMetadata<'_>,
            req: GetBlobRequestView<'a>,
            resp: &mut GetBlobResponseBuilder<'b>,
        ) -> Result<(), GrpcStatus<'static>> {
            let rev = normalize_revision(req.revision().unwrap_or(""));
            let path = req.path().unwrap_or("");
            let content = b"fn main() {}\n";
            resp.write_content(content)
                .write_truncated(false)
                .write_is_binary(false)
                .write_size(content.len() as u64)
                .write_oid(SAMPLE_OID_3)
                .write_path(path)
                .write_revision(rev);
            Ok(())
        }

        fn list_commits<'a, 'b>(
            &self,
            _meta: &mut RpcMetadata<'_>,
            req: ListCommitsRequestView<'a>,
            resp: &mut ListCommitsResponseBuilder<'b>,
        ) -> Result<(), GrpcStatus<'static>> {
            let rev = normalize_revision(req.revision().unwrap_or(""));
            let limit = req.limit().unwrap_or(20);
            resp.write_has_more(limit == 1)
                .write_commits(|c| {
                    c.write_message("Stub commit")
                        .write_subject("Stub commit")
                        .write_committer_time_secs(1_700_000_000)
                        .write_committer_email("stub@git.test")
                        .write_committer_name("Stub")
                        .write_author_time_secs(1_700_000_000)
                        .write_author_email("stub@git.test")
                        .write_author_name("Stub")
                        .write_oid(SAMPLE_OID_1);
                })
                .write_revision(rev);
            Ok(())
        }

        fn get_commit<'a, 'b>(
            &self,
            _meta: &mut RpcMetadata<'_>,
            req: GetCommitRequestView<'a>,
            resp: &mut GetCommitResponseBuilder<'b>,
        ) -> Result<(), GrpcStatus<'static>> {
            let rev = normalize_revision(req.revision().unwrap_or(""));
            resp.write_patch("@@ -0,0 +1 @@\n+fn main() {}\n")
                .write_total_deletions(0)
                .write_total_additions(1)
                .write_files(|f| {
                    f.write_patch("@@ -0,0 +1 @@\n+fn main() {}\n")
                        .write_deletions(0)
                        .write_additions(1)
                        .write_status(DIFF_STATUS_ADDED)
                        .write_path("src/main.rs");
                })
                .write_commit(|c| {
                    c.write_message("Add main.rs")
                        .write_subject("Add main.rs")
                        .write_committer_time_secs(1_700_000_000)
                        .write_committer_email("stub@git.test")
                        .write_committer_name("Stub")
                        .write_author_time_secs(1_700_000_000)
                        .write_author_email("stub@git.test")
                        .write_author_name("Stub")
                        .write_oid(rev);
                });
            Ok(())
        }
    }

    #[test]
    fn dispatches_http_proxy_routes_and_grpc_methods() {
        let server = GitServiceServer::new(StubGitService);
        let mut scratch = [0u8; 1024];
        let mut out_buf = [0u8; 2048];

        // 1. HTTP GET /api/v1/auth/status
        let auth_http_req = HttpRequest::from_uri(HttpMethod::Get, API_AUTH_STATUS_PATH, None, &[]);
        let mut writer = BackwardWriter::new(&mut out_buf);
        let http_resp = server
            .call_http(&auth_http_req, &mut scratch, &mut writer)
            .expect("route matched")
            .expect("handler succeeded");
        assert_eq!(http_resp.status_code, 200);
        let auth_view = GetAuthStatusResponseView::from_bytes(http_resp.body).unwrap();
        assert!(auth_view.authenticated().unwrap());
        assert_eq!(auth_view.username().unwrap(), "tester");
        assert_eq!(auth_view.ssh_host().unwrap(), "git.test");

        // 2. HTTP GET /api/v1/repositories?scope=teams&owner=infra&visibility=private&query=deploy
        let repos_http_req = HttpRequest::from_uri(
            HttpMethod::Get,
            "/api/v1/repositories?scope=teams&owner=infra&visibility=private&query=deploy",
            None,
            &[],
        );
        let mut writer = BackwardWriter::new(&mut out_buf);
        let http_resp = server
            .call_http(&repos_http_req, &mut scratch, &mut writer)
            .expect("route matched")
            .expect("handler succeeded");
        assert_eq!(http_resp.status_code, 200);
        let repos_view = ListRepositoriesResponseView::from_bytes(http_resp.body).unwrap();
        let mut iter = repos_view.repositories();
        let repo = iter.next().expect("one repo").expect("valid repo view");
        assert_eq!(repo.scope().unwrap(), "teams");
        assert_eq!(repo.owner().unwrap(), "infra");
        assert_eq!(repo.visibility().unwrap(), "private");
        assert_eq!(repo.name().unwrap(), "deploy");
        assert_eq!(
            repo.canonical_path().unwrap(),
            "/teams/infra/private/deploy.git"
        );

        // 3. HTTP GET /api/v1/repositories/{scope}/{owner}/{visibility}/{name}?revision=v1.0.0
        let get_repo_http_req = HttpRequest::from_uri(
            HttpMethod::Get,
            "/api/v1/repositories/users/alice/public/ro-git?revision=v1.0.0",
            None,
            &[],
        );
        let mut writer = BackwardWriter::new(&mut out_buf);
        let http_resp = server
            .call_http(&get_repo_http_req, &mut scratch, &mut writer)
            .expect("GetRepository route matched")
            .expect("GetRepository handler succeeded");
        assert_eq!(http_resp.status_code, 200);
        let get_repo_view = GetRepositoryResponseView::from_bytes(http_resp.body).unwrap();
        assert_eq!(get_repo_view.resolved_revision().unwrap(), "v1.0.0");
        assert_eq!(
            get_repo_view
                .repository()
                .unwrap()
                .unwrap()
                .canonical_path()
                .unwrap(),
            "/users/alice/public/ro-git.git"
        );

        // 4. HTTP GET /api/v1/repositories/{scope}/{owner}/{visibility}/{name}/tree
        let get_tree_http_req = HttpRequest::from_uri(
            HttpMethod::Get,
            "/api/v1/repositories/users/alice/public/ro-git/tree?revision=main&path=crates%2Fro-git-proto",
            None,
            &[],
        );
        let mut writer = BackwardWriter::new(&mut out_buf);
        let http_resp = server
            .call_http(&get_tree_http_req, &mut scratch, &mut writer)
            .expect("GetTree route matched")
            .expect("GetTree handler succeeded");
        assert_eq!(http_resp.status_code, 200);
        let get_tree_view = GetTreeResponseView::from_bytes(http_resp.body).unwrap();
        assert_eq!(get_tree_view.revision().unwrap(), "main");
        assert_eq!(get_tree_view.path().unwrap(), "crates/ro-git-proto");

        // 5. HTTP GET /api/v1/repositories/{scope}/{owner}/{visibility}/{name}/blob
        let get_blob_http_req = HttpRequest::from_uri(
            HttpMethod::Get,
            "/api/v1/repositories/users/alice/public/ro-git/blob?revision=main&path=src%2Fmain.rs",
            None,
            &[],
        );
        let mut writer = BackwardWriter::new(&mut out_buf);
        let http_resp = server
            .call_http(&get_blob_http_req, &mut scratch, &mut writer)
            .expect("GetBlob route matched")
            .expect("GetBlob handler succeeded");
        assert_eq!(http_resp.status_code, 200);
        let get_blob_view = GetBlobResponseView::from_bytes(http_resp.body).unwrap();
        assert_eq!(get_blob_view.revision().unwrap(), "main");
        assert_eq!(get_blob_view.path().unwrap(), "src/main.rs");
        assert_eq!(get_blob_view.content().unwrap(), b"fn main() {}\n");

        // 6. HTTP GET /api/v1/repositories/{scope}/{owner}/{visibility}/{name}/commits
        let list_commits_http_req = HttpRequest::from_uri(
            HttpMethod::Get,
            "/api/v1/repositories/users/alice/public/ro-git/commits?revision=main&limit=1&offset=0",
            None,
            &[],
        );
        let mut writer = BackwardWriter::new(&mut out_buf);
        let http_resp = server
            .call_http(&list_commits_http_req, &mut scratch, &mut writer)
            .expect("ListCommits route matched")
            .expect("ListCommits handler succeeded");
        assert_eq!(http_resp.status_code, 200);
        let list_commits_view = ListCommitsResponseView::from_bytes(http_resp.body).unwrap();
        assert_eq!(list_commits_view.revision().unwrap(), "main");
        assert!(list_commits_view.has_more().unwrap());
        assert_eq!(list_commits_view.commits().count(), 1);

        // 7. HTTP GET /api/v1/repositories/{scope}/{owner}/{visibility}/{name}/commit
        let get_commit_http_req = HttpRequest::from_uri(
            HttpMethod::Get,
            "/api/v1/repositories/users/alice/public/ro-git/commit?revision=0123456789abcdef0123456789abcdef01234567",
            None,
            &[],
        );
        let mut writer = BackwardWriter::new(&mut out_buf);
        let http_resp = server
            .call_http(&get_commit_http_req, &mut scratch, &mut writer)
            .expect("GetCommit route matched")
            .expect("GetCommit handler succeeded");
        assert_eq!(http_resp.status_code, 200);
        let get_commit_view = GetCommitResponseView::from_bytes(http_resp.body).unwrap();
        assert_eq!(
            get_commit_view.commit().unwrap().unwrap().oid().unwrap(),
            SAMPLE_OID_1
        );
        assert_eq!(get_commit_view.total_additions().unwrap(), 1);

        // 8. gRPC unary calls for all RPCs
        let mut ctx = RpcContext::<roto_grpc::FixedMetadata>::new();
        for method in [
            "GetAuthStatus",
            "ListRepositories",
            "GetRepository",
            "GetTree",
            "GetBlob",
            "ListCommits",
            "GetCommit",
        ] {
            let mut meta = ctx.metadata();
            let mut grpc_writer = BackwardWriter::new(&mut out_buf);
            server
                .call_unary(&mut meta, method, &[], &mut grpc_writer)
                .unwrap_or_else(|e| panic!("gRPC {method} failed: {e:?}"));
            let lpm_bytes = grpc_writer.finish().unwrap();
            assert!(lpm_bytes.len() >= 5);
        }
    }


    #[test]
    fn formats_and_parses_token_payload_and_sign_command() {
        let payload = format_token_payload("alice_01", 1_700_000_000).expect("valid username");
        assert_eq!(payload, "ro-git:v1:alice_01:1700000000");

        let (user, exp) = parse_token_payload(&payload).expect("parse payload");
        assert_eq!(user, "alice_01");
        assert_eq!(exp, 1_700_000_000);

        let cmd =
            format_ssh_keygen_sign_command("alice_01", 1_700_000_000).expect("valid sign command");
        assert_eq!(
            cmd,
            "printf 'ro-git:v1:alice_01:1700000000' | ssh-keygen -Y sign -f ~/.ssh/id_ed25519 -n ro-git"
        );

        assert!(format_token_payload("", 1_700_000_000).is_none());
        assert!(format_token_payload("alice/bob", 1_700_000_000).is_none());
        assert!(format_ssh_keygen_sign_command("bad:user", 1_700_000_000).is_none());

        assert_eq!(
            parse_token_payload("ro-git:v2:alice:1700000000"),
            Err(TokenError::InvalidVersionPrefix)
        );
        assert_eq!(
            parse_token_payload("ro-git:v1"),
            Err(TokenError::InvalidPayloadFormat)
        );
        assert_eq!(
            parse_token_payload("ro-git:v1:alice"),
            Err(TokenError::InvalidPayloadFormat)
        );
        assert_eq!(
            parse_token_payload("ro-git:v1:alice:1700000000:extra"),
            Err(TokenError::InvalidPayloadFormat)
        );
        assert_eq!(
            parse_token_payload("ro-git:v1:../alice:1700000000"),
            Err(TokenError::InvalidUsername)
        );
        assert_eq!(
            parse_token_payload("ro-git:v1:alice:notanumber"),
            Err(TokenError::InvalidExpiration)
        );
        assert_eq!(
            parse_token_payload("ro-git:v1:alice:"),
            Err(TokenError::InvalidExpiration)
        );
    }

    #[test]
    fn roundtrips_base64url_and_bearer_tokens() {
        for sample in [
            &b""[..],
            &b"a"[..],
            &b"ab"[..],
            &b"abc"[..],
            &b"ro-git:v1:alice:1700000000"[..],
            &[0x00, 0xff, 0xfe, 0xfd, 0x7f, 0x80],
        ] {
            let encoded = base64url_encode(sample);
            assert!(!encoded.contains('='));
            let decoded = base64url_decode(&encoded).expect("decode unpadded base64url");
            assert_eq!(decoded, sample);
        }

        // Accepts padded base64url as well
        assert_eq!(base64url_decode("YQ==").unwrap(), b"a");
        assert_eq!(base64url_decode("YWI=").unwrap(), b"ab");

        // Rejects invalid base64url inputs
        assert_eq!(base64url_decode("a"), Err(TokenError::InvalidBase64));
        assert_eq!(base64url_decode("YQ="), Err(TokenError::InvalidBase64));
        assert_eq!(base64url_decode("!!!!"), Err(TokenError::InvalidBase64));

        let payload = "ro-git:v1:alice:1700086400";
        let sample_pem = "\
-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAA=
-----END SSH SIGNATURE-----
";
        let token = encode_bearer_token(payload, sample_pem).expect("encode bearer token");
        let decoded = decode_bearer_token(&token).expect("decode raw token");
        assert_eq!(decoded.username, "alice");
        assert_eq!(decoded.exp_unix_secs, 1_700_086_400);
        assert_eq!(decoded.payload, payload);
        assert_eq!(decoded.sshsig_pem, sample_pem.trim());

        let with_bearer = format!("  Bearer   {token}  ");
        let decoded_bearer = decode_bearer_token(&with_bearer).expect("decode Bearer header");
        assert_eq!(decoded_bearer, decoded);

        // Rejects malformed tokens or missing PEM boundaries
        assert_eq!(decode_bearer_token(""), Err(TokenError::MalformedToken));
        assert_eq!(
            decode_bearer_token("Bearer "),
            Err(TokenError::MalformedToken)
        );
        assert_eq!(
            decode_bearer_token("no-dot-separator"),
            Err(TokenError::MalformedToken)
        );
        assert_eq!(
            decode_bearer_token("a.b.c"),
            Err(TokenError::MalformedToken)
        );
        assert_eq!(
            encode_bearer_token(payload, "not a pem"),
            Err(TokenError::InvalidSignaturePem)
        );
        assert_eq!(
            encode_bearer_token(
                payload,
                "-----BEGIN SSH SIGNATURE-----\n   \n-----END SSH SIGNATURE-----"
            ),
            Err(TokenError::InvalidSignaturePem)
        );
    }

    #[test]
    fn validates_token_claims_ttl_and_expiration() {
        let now = 1_700_000_000;
        let max_ttl = 2_592_000; // 30 days

        assert_eq!(
            validate_token_claims("alice", now + 3_600, now, max_ttl),
            Ok(())
        );
        assert_eq!(
            validate_token_claims("alice", now + max_ttl, now, max_ttl),
            Ok(())
        );
        assert_eq!(
            validate_token_claims("alice", now, now, max_ttl),
            Err(TokenError::TokenExpired)
        );
        assert_eq!(
            validate_token_claims("alice", now - 1, now, max_ttl),
            Err(TokenError::TokenExpired)
        );
        assert_eq!(
            validate_token_claims("alice", now + max_ttl + 1, now, max_ttl),
            Err(TokenError::TokenTtlExceeded)
        );
        assert_eq!(
            validate_token_claims("bad/user", now + 60, now, max_ttl),
            Err(TokenError::InvalidUsername)
        );
    }
}
