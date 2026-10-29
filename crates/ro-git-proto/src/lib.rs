#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::format;
use alloc::string::String;

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
}
