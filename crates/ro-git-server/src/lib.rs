//! `ro-git-server` backend library implementing the `roto-grpc` `GitService`
//! and privilege-separated `git-worker` IPC contract.

use ro_git_proto::grpc::ro_git::v1::git_service::{GitService, GitServiceServer};
use ro_git_proto::ro_git::v1::{
    GetAuthStatusRequestView, GetAuthStatusResponseBuilder, ListRepositoriesRequestView,
    ListRepositoriesResponseBuilder,
};
use roto_grpc::{GrpcStatus, RpcMetadata};

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
}

impl GitService for GitServiceHandler {
    fn get_auth_status<'a, 'b>(
        &self,
        _meta: &mut RpcMetadata<'_>,
        _req: GetAuthStatusRequestView<'a>,
        resp: &mut GetAuthStatusResponseBuilder<'b>,
    ) -> Result<(), GrpcStatus<'static>> {
        resp.write_ssh_host(&self.config.ssh_host);
        if let Some(ref user) = self.config.dev_user {
            resp.write_username(user).write_authenticated(true);
        } else {
            resp.write_username("").write_authenticated(false);
        }
        Ok(())
    }

    fn list_repositories<'a, 'b>(
        &self,
        _meta: &mut RpcMetadata<'_>,
        _req: ListRepositoriesRequestView<'a>,
        resp: &mut ListRepositoriesResponseBuilder<'b>,
    ) -> Result<(), GrpcStatus<'static>> {
        resp.write_ssh_host(&self.config.ssh_host);
        if let Some(ref user) = self.config.dev_user {
            resp.write_authenticated_user(user);
        } else {
            resp.write_authenticated_user("");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ro_git_proto::ro_git::v1::{GetAuthStatusResponseView, ListRepositoriesResponseView};
    use ro_git_proto::{API_AUTH_STATUS_PATH, API_REPOSITORIES_PATH};
    use roto::runtime::BackwardWriter;
    use roto_grpc::http::{HttpMethod, HttpRequest};

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
        let mut cfg = ServerConfig::default();
        cfg.ssh_host = String::from("git.team.internal");
        cfg.dev_user = Some(String::from("charles"));
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
}
