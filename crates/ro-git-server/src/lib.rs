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
        let mut cfg = Self::default();
        if let Ok(val) = std::env::var("RO_GIT_LISTEN_ADDR") {
            if !val.trim().is_empty() {
                cfg.listen_addr = val;
            }
        }
        if let Ok(val) = std::env::var("RO_GIT_ROOT") {
            if !val.trim().is_empty() {
                cfg.root_dir = val;
            }
        }
        if let Ok(val) = std::env::var("RO_GIT_SSH_HOST") {
            if !val.trim().is_empty() {
                cfg.ssh_host = val;
            }
        }
        if let Ok(val) = std::env::var("RO_GIT_STATIC_DIR") {
            if !val.trim().is_empty() {
                cfg.static_dir = val;
            }
        }
        if let Ok(val) = std::env::var("RO_GIT_MAX_TOKEN_TTL_SECS") {
            if let Ok(parsed) = val.trim().parse::<u64>() {
                cfg.max_token_ttl_secs = parsed;
            }
        }
        if let Ok(val) = std::env::var("RO_GIT_NOBODY_UID") {
            if let Ok(parsed) = val.trim().parse::<u32>() {
                cfg.nobody_uid = parsed;
            }
        }
        if let Ok(val) = std::env::var("RO_GIT_DEV_USER") {
            let trimmed = val.trim();
            if !trimmed.is_empty() {
                cfg.dev_user = Some(trimmed.to_owned());
            }
        }
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
    fn git_service_handler_serves_auth_status_and_repositories_over_http() {
        let mut cfg = ServerConfig::default();
        cfg.ssh_host = String::from("git.team.internal");
        cfg.dev_user = Some(String::from("charles"));
        let server = GitServiceHandler::new(cfg).into_server();

        let mut scratch = [0u8; 512];
        let mut out_buf = [0u8; 512];

        let auth_req = HttpRequest::from_uri(HttpMethod::Get, API_AUTH_STATUS_PATH, None, &[]);
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

        let repos_req = HttpRequest::from_uri(HttpMethod::Get, API_REPOSITORIES_PATH, None, &[]);
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
