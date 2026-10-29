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
        GetAuthStatusResponseView, ListRepositoriesRequestBuilder, ListRepositoriesRequestView,
        ListRepositoriesResponseBuilder, ListRepositoriesResponseView, WorkerRequestBuilder,
        WorkerRequestView, WorkerResponseBuilder, WorkerResponseView,
    };
    use alloc::vec::Vec;
    use roto::runtime::BackwardWriter;
    use roto_grpc::http::{HttpMethod, HttpRequest};
    use roto_grpc::{GrpcStatus, RpcContext, RpcMetadata};

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
    fn validates_scopes_visibilities_and_identifiers() {
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
    fn roundtrips_worker_ipc_envelopes() {
        let mut req_buf = [0u8; 512];
        let mut req_builder = WorkerRequestBuilder::new(&mut req_buf);
        req_builder
            .write_list_repositories(|lr| {
                lr.write_scope("users").write_owner("alice");
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
    }

    #[test]
    fn dispatches_http_proxy_routes_and_grpc_methods() {
        let server = GitServiceServer::new(StubGitService);
        let mut scratch = [0u8; 512];
        let mut out_buf = [0u8; 1024];

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

        // 3. gRPC unary call
        let mut ctx = RpcContext::<roto_grpc::FixedMetadata>::new();
        let mut meta = ctx.metadata();
        let mut grpc_writer = BackwardWriter::new(&mut out_buf);
        server
            .call_unary(&mut meta, "GetAuthStatus", &[], &mut grpc_writer)
            .expect("gRPC GetAuthStatus");
        let lpm_bytes = grpc_writer.finish().unwrap();
        assert!(lpm_bytes.len() > 5);
        let grpc_view = GetAuthStatusResponseView::from_bytes(&lpm_bytes[5..]).unwrap();
        assert!(grpc_view.authenticated().unwrap());
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
