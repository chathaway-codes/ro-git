#![forbid(unsafe_code)]

use std::fmt::Write as _;
use std::io::Write;
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use nix::unistd::{geteuid, User};
use ro_git_proto::grpc::ro_git::v1::git_service::GitServiceClient;
use ro_git_proto::ro_git::v1::{ListRepositoriesRequestBuilder, RepositoryInfoView};
use ro_git_proto::{
    encode_bearer_token, format_authenticated_ssh_url, format_token_payload, is_valid_identifier,
    is_valid_revision, strip_git_suffix, DEFAULT_REVISION, SCOPE_TEAMS, SCOPE_USERS,
    SSH_SIG_NAMESPACE, VISIBILITY_PRIVATE, VISIBILITY_PUBLIC,
};
use roto_grpc::{DynamicMetadata, GrpcClient, StdClientTransport};
use ssh_key::{HashAlg, LineEnding, PrivateKey};

/// Default gRPC server address when neither `--addr` nor `RO_GIT_ADDR` is provided.
pub const DEFAULT_GRPC_ADDR: &str = "127.0.0.1:8080";

/// Default Git remote name used by `push` when `--remote` is not provided.
pub const DEFAULT_GIT_REMOTE: &str = "origin";

/// Default bearer token lifetime in seconds (5 minutes).
pub const DEFAULT_TOKEN_TTL_SECS: u64 = 300;

/// TCP connection and socket I/O timeout in seconds.
const TCP_TIMEOUT_SECS: u64 = 10;

/// Candidate private key filenames searched under `~/.ssh/` when no explicit key is provided.
pub const DEFAULT_SSH_KEY_NAMES: [&str; 2] = ["id_ed25519", "id_rsa"];

/// Usage banner printed for `-h` / `--help` / `help`.
pub const USAGE: &str = "\
Usage: ro-git-cli [OPTIONS] [COMMAND]

Commands:
  list [QUERY]          List or search repositories (default)
  search <QUERY>        Search repositories by substring query
  user [OWNER] [QUERY]  Shortcut: list a user's public and private repositories
  push [REPO] [REF]     Add git remote (default: origin) if needed and run git push
  help                  Show this help message

Options:
  -a, --addr <ADDR>          gRPC server address [env: RO_GIT_ADDR] [default: 127.0.0.1:8080]
  -i, --key <PATH>           SSH private key path [env: RO_GIT_SSH_KEY] [default: ~/.ssh/id_ed25519]
  -u, --user <USER>          Username for SSH auth and user shortcut [env: RO_GIT_USER, USER]
      --no-auth              Send unauthenticated request without signing an SSH token
  -m, --mine                 Shortcut: filter to current user's public and private repositories
  -r, --remote <REMOTE>      Git remote name for push [default: origin]
  -s, --scope <SCOPE>        Filter or target scope (users | teams)
  -o, --owner <OWNER>        Filter or target owner name
  -v, --visibility <VIS>     Filter or target visibility (public | private)
  -q, --query <QUERY>        Filter by case-insensitive substring query
  -h, --help                 Show this help message
";

/// Process environment snapshot used for CLI configuration resolution.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CliEnv {
    pub addr: Option<String>,
    pub user: Option<String>,
    pub ssh_key: Option<PathBuf>,
    pub home: Option<PathBuf>,
    pub cwd: Option<PathBuf>,
}

impl CliEnv {
    /// Captures CLI-relevant environment variables and OS user fallbacks from the current process.
    #[must_use]
    pub fn from_process() -> Self {
        let os_user = User::from_uid(geteuid()).ok().flatten();
        let addr = non_empty_env("RO_GIT_ADDR");
        let user = non_empty_env("RO_GIT_USER")
            .or_else(|| non_empty_env("USER"))
            .or_else(|| non_empty_env("LOGNAME"))
            .or_else(|| os_user.as_ref().map(|u| u.name.clone()));
        let ssh_key = non_empty_env("RO_GIT_SSH_KEY").map(PathBuf::from);
        let home = non_empty_env("HOME")
            .map(PathBuf::from)
            .or_else(|| os_user.map(|u| u.dir));
        let cwd = std::env::current_dir().ok();

        Self {
            addr,
            user,
            ssh_key,
            home,
            cwd,
        }
    }
}

fn non_empty_env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|v| v.trim().to_owned())
        .filter(|v| !v.is_empty())
}

/// Authentication mode for a CLI gRPC request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthSelection {
    /// Authenticate with an SSH bearer token signed by an explicit or default SSH private key.
    SshKey {
        user: String,
        key_path: Option<PathBuf>,
        home: Option<PathBuf>,
    },
    /// Do not attach an `authorization` metadata header.
    NoAuth,
}

/// Resolved configuration for a `ListRepositories` gRPC request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CliConfig {
    pub addr: String,
    pub auth: AuthSelection,
    pub scope: String,
    pub owner: String,
    pub visibility: String,
    pub query: String,
}

/// Resolved configuration for the `push` command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PushConfig {
    pub client: CliConfig,
    pub remote: String,
    pub repo: Option<String>,
    pub refspec: String,
    pub cwd: PathBuf,
}

/// Parsed CLI command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command {
    Help,
    List(CliConfig),
    Push(PushConfig),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SubcommandMode {
    List,
    Search,
    User,
    Push,
}

/// Parses command-line arguments and environment fallbacks into a [`Command`].
pub fn parse_args<I, S>(args: I, env: &CliEnv) -> Result<Command, String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut iter = args.into_iter();
    let mut addr: Option<String> = None;
    let mut user: Option<String> = None;
    let mut key_path: Option<PathBuf> = None;
    let mut no_auth = false;
    let mut mine_flag = false;
    let mut remote: Option<String> = None;
    let mut scope: Option<String> = None;
    let mut owner: Option<String> = None;
    let mut visibility: Option<String> = None;
    let mut query: Option<String> = None;
    let mut positionals: Vec<String> = Vec::new();
    let mut double_dash = false;
    let mut first_positional_after_double_dash = false;

    while let Some(raw_arg) = iter.next() {
        let arg = raw_arg.as_ref();
        if double_dash {
            if positionals.is_empty() {
                first_positional_after_double_dash = true;
            }
            positionals.push(arg.to_owned());
            continue;
        }
        if arg == "--" {
            double_dash = true;
            continue;
        }
        if arg == "-h" || arg == "--help" {
            return Ok(Command::Help);
        }
        if arg == "--no-auth" {
            no_auth = true;
            continue;
        }
        if arg == "-m" || arg == "--mine" {
            mine_flag = true;
            continue;
        }
        if let Some(val) = match_opt_value(arg, &mut iter, &["-r", "--remote"])? {
            remote = Some(val);
            continue;
        }
        if let Some(val) = match_opt_value(arg, &mut iter, &["-a", "--addr"])? {
            addr = Some(val);
            continue;
        }
        if let Some(val) = match_opt_value(arg, &mut iter, &["-u", "--user"])? {
            let trimmed = val.trim();
            if trimmed.is_empty() {
                return Err("username must not be empty".to_owned());
            }
            user = Some(trimmed.to_owned());
            continue;
        }
        if let Some(val) = match_opt_value(arg, &mut iter, &["-i", "--key"])? {
            let trimmed = val.trim();
            if trimmed.is_empty() {
                return Err("SSH key path must not be empty".to_owned());
            }
            key_path = Some(PathBuf::from(trimmed));
            continue;
        }
        if let Some(val) = match_opt_value(arg, &mut iter, &["-s", "--scope"])? {
            scope = Some(val);
            continue;
        }
        if let Some(val) = match_opt_value(arg, &mut iter, &["-o", "--owner"])? {
            let trimmed = val.trim();
            if !is_valid_identifier(trimmed) {
                return Err(format!("invalid owner name: {trimmed}"));
            }
            owner = Some(trimmed.to_owned());
            continue;
        }
        if let Some(val) = match_opt_value(arg, &mut iter, &["-v", "--visibility"])? {
            visibility = Some(val);
            continue;
        }
        if let Some(val) = match_opt_value(arg, &mut iter, &["-q", "--query"])? {
            query = Some(val);
            continue;
        }
        if arg.starts_with('-') {
            return Err(format!("unknown option: {arg}"));
        }
        positionals.push(arg.to_owned());
    }

    if !first_positional_after_double_dash && positionals.first().map(String::as_str) == Some("help") {
        return Ok(Command::Help);
    }

    let (mode, rest_positionals) = if first_positional_after_double_dash {
        (SubcommandMode::List, &positionals[..])
    } else {
        match positionals.first().map(String::as_str) {
            None => (SubcommandMode::List, &positionals[..]),
            Some("list") => (SubcommandMode::List, &positionals[1..]),
            Some("search") => (SubcommandMode::Search, &positionals[1..]),
            Some("user") => (SubcommandMode::User, &positionals[1..]),
            Some("push") => (SubcommandMode::Push, &positionals[1..]),
            Some(_) => (SubcommandMode::List, &positionals[..]),
        }
    };

    if mode != SubcommandMode::Push && remote.is_some() {
        return Err("--remote is only supported with the push command".to_owned());
    }

    let mut push_repo: Option<String> = None;
    let mut push_refspec = DEFAULT_REVISION.to_owned();

    match mode {
        SubcommandMode::List | SubcommandMode::Search => {
            if rest_positionals.len() > 1 {
                return Err(format!("unexpected argument: {}", rest_positionals[1]));
            }
            if let Some(pos_query) = rest_positionals.first() {
                if query.is_some() {
                    return Err(
                        "query specified both via --query and positional argument".to_owned()
                    );
                }
                query = Some(pos_query.clone());
            }
            if mode == SubcommandMode::Search
                && query.as_deref().is_none_or(|q| q.trim().is_empty())
            {
                return Err("search requires a non-empty query".to_owned());
            }
        }
        SubcommandMode::User => {
            if rest_positionals.len() > 2 {
                return Err(format!("unexpected argument: {}", rest_positionals[2]));
            }
            if let Some(pos_owner) = rest_positionals.first() {
                if owner.is_some() {
                    return Err(
                        "owner specified both via --owner and positional argument".to_owned()
                    );
                }
                let trimmed_owner = pos_owner.trim();
                if !is_valid_identifier(trimmed_owner) {
                    return Err(format!("invalid owner name: {trimmed_owner}"));
                }
                owner = Some(trimmed_owner.to_owned());
            }
            if let Some(pos_query) = rest_positionals.get(1) {
                if query.is_some() {
                    return Err(
                        "query specified both via --query and positional argument".to_owned()
                    );
                }
                query = Some(pos_query.clone());
            }
        }
        SubcommandMode::Push => {
            if mine_flag {
                return Err("--mine is not supported with the push command".to_owned());
            }
            if query.is_some() {
                return Err("--query is not supported with the push command".to_owned());
            }
            if rest_positionals.len() > 2 {
                return Err(format!("unexpected argument: {}", rest_positionals[2]));
            }
            if let Some(raw_repo) = rest_positionals.first() {
                let base = strip_git_suffix(raw_repo.trim());
                if !is_valid_identifier(base) {
                    return Err(format!("invalid repository name: {}", raw_repo.trim()));
                }
                push_repo = Some(base.to_owned());
            }
            if let Some(raw_ref) = rest_positionals.get(1) {
                let trimmed_ref = raw_ref.trim();
                if !is_valid_revision(trimmed_ref) {
                    return Err(format!("invalid git revision: {trimmed_ref}"));
                }
                push_refspec = trimmed_ref.to_owned();
            }
        }
    }

    let resolved_user = user
        .or_else(|| env.user.clone())
        .map(|u| u.trim().to_owned())
        .filter(|u| !u.is_empty());

    let is_user_shortcut = mine_flag || mode == SubcommandMode::User;
    if is_user_shortcut {
        if let Some(ref existing_scope) = scope {
            if !existing_scope.trim().eq_ignore_ascii_case(SCOPE_USERS) {
                return Err(format!(
                    "user repositories shortcut conflicts with --scope {existing_scope}"
                ));
            }
        }
        scope = Some(SCOPE_USERS.to_owned());
        if owner.is_none() {
            let shortcut_owner = resolved_user.clone().ok_or_else(|| {
                "cannot determine username for user repositories shortcut; pass --user <USER> or --owner <OWNER>".to_owned()
            })?;
            owner = Some(shortcut_owner);
        }
    }

    let final_scope = normalize_scope(scope.as_deref().unwrap_or(""))?;
    let final_visibility = normalize_visibility(visibility.as_deref().unwrap_or(""))?;
    let final_owner = owner.unwrap_or_default().trim().to_owned();
    if !final_owner.is_empty() && !is_valid_identifier(&final_owner) {
        return Err(format!("invalid owner name: {final_owner}"));
    }
    let final_query = query.unwrap_or_default().trim().to_owned();

    let raw_addr = addr
        .or_else(|| env.addr.clone())
        .unwrap_or_else(|| DEFAULT_GRPC_ADDR.to_owned());
    let normalized_addr = parse_grpc_authority(&raw_addr)?;

    let auth = if no_auth {
        AuthSelection::NoAuth
    } else {
        let auth_user = resolved_user.ok_or_else(|| {
            "cannot determine username for SSH authentication; pass --user <USER> or --no-auth"
                .to_owned()
        })?;
        if !is_valid_identifier(&auth_user) {
            return Err(format!("invalid username: {auth_user}"));
        }
        AuthSelection::SshKey {
            user: auth_user,
            key_path: key_path.or_else(|| env.ssh_key.clone()),
            home: env.home.clone(),
        }
    };

    let client_config = CliConfig {
        addr: normalized_addr,
        auth,
        scope: final_scope,
        owner: final_owner,
        visibility: final_visibility,
        query: final_query,
    };

    if mode == SubcommandMode::Push {
        let final_remote = remote
            .map(|r| r.trim().to_owned())
            .unwrap_or_else(|| DEFAULT_GIT_REMOTE.to_owned());
        if !is_valid_identifier(&final_remote) {
            return Err(format!("invalid git remote name: {final_remote}"));
        }
        let cwd = env
            .cwd
            .clone()
            .unwrap_or_else(|| PathBuf::from("."));
        return Ok(Command::Push(PushConfig {
            client: client_config,
            remote: final_remote,
            repo: push_repo,
            refspec: push_refspec,
            cwd,
        }));
    }

    Ok(Command::List(client_config))
}

fn match_opt_value<I, S>(
    arg: &str,
    iter: &mut I,
    flags: &[&str],
) -> Result<Option<String>, String>
where
    I: Iterator<Item = S>,
    S: AsRef<str>,
{
    for flag in flags {
        if arg == *flag {
            let val = iter
                .next()
                .ok_or_else(|| format!("missing value for {flag}"))?;
            return Ok(Some(val.as_ref().to_owned()));
        }
        if flag.starts_with("--") {
            if let Some(rest) = arg.strip_prefix(flag) {
                if let Some(val) = rest.strip_prefix('=') {
                    return Ok(Some(val.to_owned()));
                }
            }
        }
    }
    Ok(None)
}

fn normalize_scope(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(String::new());
    }
    if trimmed.eq_ignore_ascii_case(SCOPE_USERS) {
        return Ok(SCOPE_USERS.to_owned());
    }
    if trimmed.eq_ignore_ascii_case(SCOPE_TEAMS) {
        return Ok(SCOPE_TEAMS.to_owned());
    }
    Err(format!(
        "invalid scope '{trimmed}': expected '{SCOPE_USERS}' or '{SCOPE_TEAMS}'"
    ))
}

fn normalize_visibility(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(String::new());
    }
    if trimmed.eq_ignore_ascii_case(VISIBILITY_PUBLIC) {
        return Ok(VISIBILITY_PUBLIC.to_owned());
    }
    if trimmed.eq_ignore_ascii_case(VISIBILITY_PRIVATE) {
        return Ok(VISIBILITY_PRIVATE.to_owned());
    }
    Err(format!(
        "invalid visibility '{trimmed}': expected '{VISIBILITY_PUBLIC}' or '{VISIBILITY_PRIVATE}'"
    ))
}

/// Parses and normalizes a gRPC endpoint (`"host:port"`, `"http://host:port"`, or
/// `"grpc://host:port"`) into an HTTP/2 `host:port` authority string.
pub fn parse_grpc_authority(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("gRPC address must not be empty".to_owned());
    }

    let without_scheme = if let Some(rest) = trimmed.strip_prefix("http://") {
        rest
    } else if let Some(rest) = trimmed.strip_prefix("grpc://") {
        rest
    } else if trimmed.contains("://") {
        return Err(format!(
            "unsupported URI scheme in gRPC address '{trimmed}': expected http:// or grpc://"
        ));
    } else {
        trimmed
    };

    let authority = without_scheme.strip_suffix('/').unwrap_or(without_scheme);
    if authority.is_empty()
        || authority.contains('/')
        || authority.chars().any(char::is_whitespace)
    {
        return Err(format!("invalid gRPC address: '{trimmed}'"));
    }

    let has_port = if let Some(rest) = authority.strip_prefix('[') {
        rest.split_once("]:").is_some_and(|(host, port)| {
            !host.is_empty()
                && !host.contains(['[', ']'])
                && port.parse::<u16>().is_ok_and(|p| p > 0)
        })
    } else {
        authority.rsplit_once(':').is_some_and(|(host, port)| {
            !host.is_empty()
                && !host.contains([':', '[', ']'])
                && port.parse::<u16>().is_ok_and(|p| p > 0)
        })
    };

    if !has_port {
        return Err(format!(
            "gRPC address must include host and port (e.g. 127.0.0.1:8080): '{trimmed}'"
        ));
    }

    Ok(authority.to_owned())
}

/// Resolves the SSH private key path, using either the explicit path or the first existing
/// default key in `~/.ssh/` (`id_ed25519`, `id_rsa`).
pub fn resolve_ssh_key_path(
    explicit_key: Option<&Path>,
    home: Option<&Path>,
) -> Result<PathBuf, String> {
    if let Some(path) = explicit_key {
        if path.is_file() {
            return Ok(path.to_path_buf());
        }
        return Err(format!("SSH private key not found: {}", path.display()));
    }

    let home_dir = home.ok_or_else(|| {
        "cannot locate default SSH key: HOME directory is not set (pass --key <PATH>)".to_owned()
    })?;
    let ssh_dir = home_dir.join(".ssh");
    for name in DEFAULT_SSH_KEY_NAMES {
        let candidate = ssh_dir.join(name);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }

    Err(format!(
        "no default SSH key found in {} (checked {}); pass --key <PATH> or --no-auth",
        ssh_dir.display(),
        DEFAULT_SSH_KEY_NAMES.join(", ")
    ))
}

/// Signs a stateless `ro-git` bearer token (`<base64url(payload)>.<base64url(sshsig_pem)>`)
/// using the OpenSSH private key at `key_path`.
pub fn sign_bearer_token_file(
    key_path: &Path,
    username: &str,
    exp_unix_secs: u64,
) -> Result<String, String> {
    let payload = format_token_payload(username, exp_unix_secs)
        .ok_or_else(|| format!("invalid username: {username}"))?;
    let priv_key = PrivateKey::read_openssh_file(key_path).map_err(|e| {
        format!(
            "failed to load OpenSSH private key '{}': {e}",
            key_path.display()
        )
    })?;
    sign_token_payload(&priv_key, &payload)
}

/// Signs a stateless `ro-git` bearer token using an in-memory [`PrivateKey`].
pub fn sign_bearer_token(
    priv_key: &PrivateKey,
    username: &str,
    exp_unix_secs: u64,
) -> Result<String, String> {
    let payload = format_token_payload(username, exp_unix_secs)
        .ok_or_else(|| format!("invalid username: {username}"))?;
    sign_token_payload(priv_key, &payload)
}

fn sign_token_payload(priv_key: &PrivateKey, payload: &str) -> Result<String, String> {
    let sig = priv_key
        .sign(SSH_SIG_NAMESPACE, HashAlg::Sha512, payload.as_bytes())
        .map_err(|e| format!("failed to sign SSH token payload: {e}"))?;
    let pem = sig
        .to_pem(LineEnding::LF)
        .map_err(|e| format!("failed to encode SSH signature PEM: {e}"))?;
    encode_bearer_token(payload, &pem)
        .map_err(|e| format!("failed to encode bearer token: {e:?}"))
}

/// Decoded repository entry returned by `ListRepositories`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepositoryRecord {
    pub scope: String,
    pub owner: String,
    pub visibility: String,
    pub name: String,
    pub ssh_url: String,
}

impl RepositoryRecord {
    #[must_use]
    fn from_view(view: &RepositoryInfoView<'_>) -> Self {
        Self {
            scope: view.scope().unwrap_or("").to_owned(),
            owner: view.owner().unwrap_or("").to_owned(),
            visibility: view.visibility().unwrap_or("").to_owned(),
            name: view.name().unwrap_or("").to_owned(),
            ssh_url: view.ssh_url().unwrap_or("").to_owned(),
        }
    }
}

struct RepositoriesSnapshot {
    ssh_host: String,
    authenticated_user: String,
    repositories: Vec<RepositoryRecord>,
}

/// Encodes a `ListRepositoriesRequest` protobuf payload.
pub fn encode_list_repositories_request(
    scope: &str,
    owner: &str,
    visibility: &str,
    query: &str,
) -> Result<Vec<u8>, String> {
    let cap = scope
        .len()
        .saturating_add(owner.len())
        .saturating_add(visibility.len())
        .saturating_add(query.len())
        .saturating_add(64);
    let mut buf = vec![0u8; cap];
    let mut builder = ListRepositoriesRequestBuilder::new(&mut buf);
    builder
        .write_query(query)
        .write_visibility(visibility)
        .write_owner(owner)
        .write_scope(scope);
    let bytes = builder
        .finish()
        .map_err(|e| format!("failed to encode ListRepositoriesRequest: {e:?}"))?;
    Ok(bytes.to_vec())
}

fn fetch_repositories_snapshot(config: &CliConfig) -> Result<RepositoriesSnapshot, String> {
    let authority = parse_grpc_authority(&config.addr)?;
    let bearer_header = match &config.auth {
        AuthSelection::NoAuth => None,
        AuthSelection::SshKey {
            user,
            key_path,
            home,
        } => {
            let resolved_key = resolve_ssh_key_path(key_path.as_deref(), home.as_deref())?;
            let now_secs = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| format!("system clock error: {e}"))?
                .as_secs();
            let token = sign_bearer_token_file(
                &resolved_key,
                user,
                now_secs.saturating_add(DEFAULT_TOKEN_TTL_SECS),
            )?;
            Some(format!("Bearer {token}"))
        }
    };

    let sock_addr = authority
        .to_socket_addrs()
        .map_err(|e| format!("failed to resolve gRPC address '{authority}': {e}"))?
        .next()
        .ok_or_else(|| format!("no socket addresses resolved for '{authority}'"))?;

    let timeout = Duration::from_secs(TCP_TIMEOUT_SECS);
    let tcp = TcpStream::connect_timeout(&sock_addr, timeout)
        .map_err(|e| format!("failed to connect to '{authority}': {e}"))?;
    let _ = tcp.set_nodelay(true);
    let _ = tcp.set_read_timeout(Some(timeout));
    let _ = tcp.set_write_timeout(Some(timeout));

    let mut tx_buf = vec![0u8; 65_536];
    let mut call_buf = vec![0u8; 65_536];
    let grpc_client = GrpcClient::<4, 16_384, DynamicMetadata>::with_metadata_store(
        "http",
        &authority,
        &mut tx_buf,
    );
    let transport =
        StdClientTransport::<TcpStream, 4, 16_384, 4096, DynamicMetadata>::with_metadata_store_and_io_buf(
            tcp,
            grpc_client,
            &mut call_buf,
        );
    let mut client = GitServiceClient::new(transport);

    if let Some(ref auth_value) = bearer_header {
        client
            .insert_metadata("authorization", auth_value)
            .map_err(|e| format!("failed to attach authorization metadata: {e:?}"))?;
    }

    let req_bytes = encode_list_repositories_request(
        &config.scope,
        &config.owner,
        &config.visibility,
        &config.query,
    )?;
    let view = client
        .list_repositories(req_bytes.as_slice())
        .map_err(|e| format!("gRPC ListRepositories failed: {e:?}"))?;

    let ssh_host = view.ssh_host().unwrap_or("localhost").to_owned();
    let authenticated_user = view.authenticated_user().unwrap_or("").to_owned();
    let mut repositories = Vec::new();
    for item in view.repositories() {
        let repo_view = item.map_err(|e| format!("corrupt repository entry in response: {e:?}"))?;
        repositories.push(RepositoryRecord::from_view(&repo_view));
    }

    Ok(RepositoriesSnapshot {
        ssh_host,
        authenticated_user,
        repositories,
    })
}

/// Executes the `ListRepositories` gRPC call using the provided [`CliConfig`].
pub fn list_repositories(config: &CliConfig) -> Result<Vec<RepositoryRecord>, String> {
    Ok(fetch_repositories_snapshot(config)?.repositories)
}

/// Resolves the target SSH remote URL for `push` using the gRPC `ListRepositories` snapshot.
///
/// If a matching repository already exists in `repositories`, its `(scope, owner, visibility, name)`
/// coordinates are used (preferring a user-scoped repository owned by the caller when multiple exist).
/// Otherwise, coordinates default to `scope = "users"`, `owner = <user>`, and `visibility = "private"`
/// (or the explicit `--scope`, `--owner`, `--visibility` flags on `config`) for on-the-fly creation.
pub fn resolve_push_remote_url(
    config: &CliConfig,
    repo_name: &str,
    ssh_host: &str,
    authenticated_user: &str,
    repositories: &[RepositoryRecord],
) -> Result<String, String> {
    let base_name = strip_git_suffix(repo_name.trim());
    if !is_valid_identifier(base_name) {
        return Err(format!("invalid repository name: {repo_name}"));
    }

    let caller_user = if !authenticated_user.trim().is_empty() {
        Some(authenticated_user.trim())
    } else if let AuthSelection::SshKey { ref user, .. } = config.auth {
        Some(user.as_str())
    } else {
        None
    };

    let matching: Vec<&RepositoryRecord> = repositories
        .iter()
        .filter(|r| {
            r.name.eq_ignore_ascii_case(base_name)
                && (config.scope.is_empty() || r.scope.eq_ignore_ascii_case(&config.scope))
                && (if !config.owner.is_empty() {
                    r.owner.eq_ignore_ascii_case(&config.owner)
                } else if r.scope.eq_ignore_ascii_case(SCOPE_USERS) {
                    caller_user.is_some_and(|u| r.owner.eq_ignore_ascii_case(u))
                } else {
                    true
                })
                && (config.visibility.is_empty()
                    || r.visibility.eq_ignore_ascii_case(&config.visibility))
        })
        .collect();

    let preferred = caller_user
        .and_then(|u| {
            matching
                .iter()
                .copied()
                .find(|r| r.scope == SCOPE_USERS && r.owner.eq_ignore_ascii_case(u))
        })
        .or_else(|| matching.first().copied());

    if let Some(existing) = preferred {
        return Ok(format_authenticated_ssh_url(
            ssh_host,
            caller_user,
            &existing.scope,
            &existing.owner,
            &existing.visibility,
            &existing.name,
        ));
    }

    let target_scope = if config.scope.is_empty() {
        SCOPE_USERS
    } else {
        config.scope.as_str()
    };
    let target_owner = if !config.owner.is_empty() {
        config.owner.as_str()
    } else if target_scope == SCOPE_TEAMS {
        return Err(
            "cannot determine team owner for new team repository; pass --owner <TEAM>".to_owned(),
        );
    } else {
        caller_user.ok_or_else(|| {
            "cannot determine repository owner for push; pass --owner <OWNER> or --user <USER>"
                .to_owned()
        })?
    };
    let target_visibility = if config.visibility.is_empty() {
        VISIBILITY_PRIVATE
    } else {
        config.visibility.as_str()
    };

    Ok(format_authenticated_ssh_url(
        ssh_host,
        caller_user,
        target_scope,
        target_owner,
        target_visibility,
        base_name,
    ))
}

/// Ensures the Git remote `config.remote` exists in `config.cwd` (adding it via the `ro-git`
/// gRPC service if missing) and runs `git push -u -- <remote> <refspec>`.
pub fn push_repository(config: &PushConfig) -> Result<(), String> {
    let toplevel_out = run_git(&config.cwd, &["rev-parse", "--show-toplevel"])?;
    let repo_root = PathBuf::from(toplevel_out.trim());

    let remote_exists = ProcessCommand::new("git")
        .current_dir(&repo_root)
        .args(["remote", "get-url", "--", &config.remote])
        .output()
        .map_err(|e| format!("failed to run git remote get-url: {e}"))?
        .status
        .success();

    if !remote_exists {
        let repo_name = match &config.repo {
            Some(explicit) => explicit.clone(),
            None => {
                let dir_name = repo_root
                    .file_name()
                    .and_then(|n| n.to_str())
                    .map(strip_git_suffix)
                    .filter(|n| is_valid_identifier(n))
                    .ok_or_else(|| {
                        format!(
                            "cannot infer valid repository name from directory '{}'; pass push <REPO>",
                            repo_root.display()
                        )
                    })?;
                dir_name.to_owned()
            }
        };

        let snapshot = fetch_repositories_snapshot(&config.client)?;
        let remote_url = resolve_push_remote_url(
            &config.client,
            &repo_name,
            &snapshot.ssh_host,
            &snapshot.authenticated_user,
            &snapshot.repositories,
        )?;
        let _ = run_git(&repo_root, &["remote", "add", "--", &config.remote, &remote_url])?;
    }

    let _ = run_git(
        &repo_root,
        &["push", "-u", "--", &config.remote, &config.refspec],
    )?;
    Ok(())
}

fn run_git(cwd: &Path, args: &[&str]) -> Result<String, String> {
    let output = ProcessCommand::new("git")
        .current_dir(cwd)
        .args(args)
        .output()
        .map_err(|e| format!("failed to execute git {}: {e}", args.first().unwrap_or(&"")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let msg = stderr.trim();
        if !msg.is_empty() {
            return Err(format!("git {} failed: {msg}", args.first().unwrap_or(&"")));
        }
        return Err(format!(
            "git {} exited with status {}",
            args.first().unwrap_or(&""),
            output.status
        ));
    }

    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Formats a single [`RepositoryRecord`] as a tab-separated plain-text line.
#[must_use]
pub fn format_repository_line(repo: &RepositoryRecord) -> String {
    format!(
        "{}/{}\t{}\t{}\t{}",
        repo.owner, repo.name, repo.visibility, repo.scope, repo.ssh_url
    )
}

/// Formats a slice of [`RepositoryRecord`]s as newline-terminated tab-separated lines.
///
/// Follows the Unix Rule of Silence: returns an empty string when `repos` is empty.
#[must_use]
pub fn format_repositories(repos: &[RepositoryRecord]) -> String {
    let mut out = String::new();
    for repo in repos {
        let _ = writeln!(out, "{}", format_repository_line(repo));
    }
    out
}

/// Entrypoint helper that parses CLI arguments, executes the command, and writes output to `stdout`.
pub fn run_with_env<I, S, W>(args: I, env: &CliEnv, stdout: &mut W) -> Result<(), String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
    W: Write,
{
    match parse_args(args, env)? {
        Command::Help => {
            stdout
                .write_all(USAGE.as_bytes())
                .map_err(|e| format!("failed to write help output: {e}"))?;
            Ok(())
        }
        Command::List(config) => {
            let repos = list_repositories(&config)?;
            let formatted = format_repositories(&repos);
            if !formatted.is_empty() {
                stdout
                    .write_all(formatted.as_bytes())
                    .map_err(|e| format!("failed to write output: {e}"))?;
            }
            Ok(())
        }
        Command::Push(config) => push_repository(&config),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ro_git_proto::decode_bearer_token;
    use ro_git_proto::ro_git::v1::ListRepositoriesRequestView;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(1);

    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new(prefix: &str) -> Self {
            let id = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "ro_git_cli_unit_{}_{}_{}",
                prefix,
                std::process::id(),
                id
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).expect("create temp dir");
            Self { path }
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn sample_env() -> CliEnv {
        CliEnv {
            addr: None,
            user: Some("alice".to_owned()),
            ssh_key: None,
            home: Some(PathBuf::from("/home/alice")),
            cwd: Some(PathBuf::from("/work/my-repo")),
        }
    }

    #[test]
    fn cli_env_from_process_captures_os_defaults() {
        let env = CliEnv::from_process();
        assert!(env.user.is_some());
        assert!(env.home.is_some());
        assert!(env.cwd.is_some());
    }

    #[test]
    fn parse_default_command_uses_default_addr_and_ssh_key_auth() {
        let env = sample_env();
        let cmd = parse_args(Vec::<&str>::new(), &env).expect("parse default args");
        assert_eq!(
            cmd,
            Command::List(CliConfig {
                addr: DEFAULT_GRPC_ADDR.to_owned(),
                auth: AuthSelection::SshKey {
                    user: "alice".to_owned(),
                    key_path: None,
                    home: Some(PathBuf::from("/home/alice")),
                },
                scope: String::new(),
                owner: String::new(),
                visibility: String::new(),
                query: String::new(),
            })
        );
    }

    #[test]
    fn parse_help_flags_and_subcommand() {
        let env = sample_env();
        for arg in ["-h", "--help", "help"] {
            assert_eq!(parse_args([arg], &env).expect("help"), Command::Help);
        }
        let mut out = Vec::new();
        run_with_env(["--help"], &env, &mut out).expect("run help");
        assert_eq!(String::from_utf8(out).expect("utf8"), USAGE);
    }

    #[test]
    fn parse_list_and_search_commands_with_filters_and_equals_syntax() {
        let env = sample_env();
        let cmd = parse_args(
            [
                "--addr=http://127.0.0.1:9090",
                "--user=charlie",
                "--key=/tmp/id_ed25519",
                "--scope=teams",
                "--owner=core",
                "--visibility=private",
                "search",
                "infra",
            ],
            &env,
        )
        .expect("parse search args");

        assert_eq!(
            cmd,
            Command::List(CliConfig {
                addr: "127.0.0.1:9090".to_owned(),
                auth: AuthSelection::SshKey {
                    user: "charlie".to_owned(),
                    key_path: Some(PathBuf::from("/tmp/id_ed25519")),
                    home: Some(PathBuf::from("/home/alice")),
                },
                scope: "teams".to_owned(),
                owner: "core".to_owned(),
                visibility: "private".to_owned(),
                query: "infra".to_owned(),
            })
        );
    }

    #[test]
    fn parse_double_dash_allows_hyphenated_and_subcommand_named_positional_query() {
        let env = sample_env();
        for query_arg in ["-my-repo", "push", "help", "search", "user"] {
            let cmd = parse_args(["--", query_arg], &env).expect("parse -- <query>");
            assert_eq!(
                cmd,
                Command::List(CliConfig {
                    addr: DEFAULT_GRPC_ADDR.to_owned(),
                    auth: AuthSelection::SshKey {
                        user: "alice".to_owned(),
                        key_path: None,
                        home: Some(PathBuf::from("/home/alice")),
                    },
                    scope: String::new(),
                    owner: String::new(),
                    visibility: String::new(),
                    query: query_arg.to_owned(),
                })
            );
        }
    }

    #[test]
    fn parse_user_repos_shortcut_defaults_to_current_user_public_and_private() {
        let env = sample_env();
        for args in [vec!["user"], vec!["--mine"], vec!["-m"]] {
            let cmd = parse_args(args, &env).expect("parse user shortcut");
            assert_eq!(
                cmd,
                Command::List(CliConfig {
                    addr: DEFAULT_GRPC_ADDR.to_owned(),
                    auth: AuthSelection::SshKey {
                        user: "alice".to_owned(),
                        key_path: None,
                        home: Some(PathBuf::from("/home/alice")),
                    },
                    scope: "users".to_owned(),
                    owner: "alice".to_owned(),
                    visibility: String::new(),
                    query: String::new(),
                })
            );
        }
    }

    #[test]
    fn parse_user_subcommand_accepts_explicit_owner_and_query() {
        let env = sample_env();
        let cmd = parse_args(["user", "bob", "widgets"], &env).expect("parse user bob widgets");
        assert_eq!(
            cmd,
            Command::List(CliConfig {
                addr: DEFAULT_GRPC_ADDR.to_owned(),
                auth: AuthSelection::SshKey {
                    user: "alice".to_owned(),
                    key_path: None,
                    home: Some(PathBuf::from("/home/alice")),
                },
                scope: "users".to_owned(),
                owner: "bob".to_owned(),
                visibility: String::new(),
                query: "widgets".to_owned(),
            })
        );
    }

    #[test]
    fn parse_push_command_defaults_to_origin_and_accepts_overrides() {
        let env = sample_env();
        let default_push = parse_args(["push"], &env).expect("parse default push");
        assert_eq!(
            default_push,
            Command::Push(PushConfig {
                client: CliConfig {
                    addr: DEFAULT_GRPC_ADDR.to_owned(),
                    auth: AuthSelection::SshKey {
                        user: "alice".to_owned(),
                        key_path: None,
                        home: Some(PathBuf::from("/home/alice")),
                    },
                    scope: String::new(),
                    owner: String::new(),
                    visibility: String::new(),
                    query: String::new(),
                },
                remote: DEFAULT_GIT_REMOTE.to_owned(),
                repo: None,
                refspec: DEFAULT_REVISION.to_owned(),
                cwd: PathBuf::from("/work/my-repo"),
            })
        );

        let custom_push = parse_args(
            [
                "push",
                "-r",
                "upstream",
                "-s",
                "teams",
                "-o",
                "core",
                "-v",
                "public",
                "docs.git",
                "main",
            ],
            &env,
        )
        .expect("parse custom push");
        assert_eq!(
            custom_push,
            Command::Push(PushConfig {
                client: CliConfig {
                    addr: DEFAULT_GRPC_ADDR.to_owned(),
                    auth: AuthSelection::SshKey {
                        user: "alice".to_owned(),
                        key_path: None,
                        home: Some(PathBuf::from("/home/alice")),
                    },
                    scope: "teams".to_owned(),
                    owner: "core".to_owned(),
                    visibility: "public".to_owned(),
                    query: String::new(),
                },
                remote: "upstream".to_owned(),
                repo: Some("docs".to_owned()),
                refspec: "main".to_owned(),
                cwd: PathBuf::from("/work/my-repo"),
            })
        );
    }

    #[test]
    fn resolve_push_remote_url_prefers_existing_repo_or_builds_new_url() {
        let config = CliConfig {
            addr: DEFAULT_GRPC_ADDR.to_owned(),
            auth: AuthSelection::SshKey {
                user: "alice".to_owned(),
                key_path: None,
                home: None,
            },
            scope: String::new(),
            owner: String::new(),
            visibility: String::new(),
            query: String::new(),
        };
        let existing = vec![
            RepositoryRecord {
                scope: "teams".to_owned(),
                owner: "core".to_owned(),
                visibility: "public".to_owned(),
                name: "docs".to_owned(),
                ssh_url: "ssh://git.example.test/teams/core/public/docs.git".to_owned(),
            },
            RepositoryRecord {
                scope: "users".to_owned(),
                owner: "bob".to_owned(),
                visibility: "public".to_owned(),
                name: "widgets".to_owned(),
                ssh_url: "ssh://git.example.test/users/bob/public/widgets.git".to_owned(),
            },
        ];

        // Matches existing team repository on server
        let existing_url =
            resolve_push_remote_url(&config, "docs", "git.example.test", "alice", &existing)
                .expect("resolve existing");
        assert_eq!(
            existing_url,
            "ssh://alice@git.example.test/teams/core/public/docs.git"
        );

        // Does NOT hijack another user's public repository when --owner is omitted
        let unowned_name_url =
            resolve_push_remote_url(&config, "widgets", "git.example.test", "alice", &existing)
                .expect("resolve widgets for alice");
        assert_eq!(
            unowned_name_url,
            "ssh://alice@git.example.test/users/alice/private/widgets.git"
        );

        // Falls back to users/<caller>/private/<repo>.git for new repository
        let new_url =
            resolve_push_remote_url(&config, "new-app", "git.example.test", "alice", &existing)
                .expect("resolve new");
        assert_eq!(
            new_url,
            "ssh://alice@git.example.test/users/alice/private/new-app.git"
        );

        // Requires explicit --owner when creating a new team repository
        let mut team_config = config.clone();
        team_config.scope = "teams".to_owned();
        assert!(resolve_push_remote_url(
            &team_config,
            "new-team-repo",
            "git.example.test",
            "alice",
            &existing,
        )
        .is_err());
    }

    #[test]
    fn parse_args_rejects_invalid_inputs_and_conflicts() {
        let env = sample_env();
        assert!(parse_args(["--unknown"], &env).is_err());
        assert!(parse_args(["--addr"], &env).is_err());
        assert!(parse_args(["search"], &env).is_err());
        assert!(parse_args(["-q", "a", "b"], &env).is_err());
        assert!(parse_args(["list", "a", "b"], &env).is_err());
        assert!(parse_args(["user", "alice", "q", "extra"], &env).is_err());
        assert!(parse_args(["user", ""], &env).is_err());
        assert!(parse_args(["--mine", "--owner", ""], &env).is_err());
        assert!(parse_args(["--user", ""], &env).is_err());
        assert!(parse_args(["--key", ""], &env).is_err());
        assert!(parse_args(["-o", "alice", "user", "bob"], &env).is_err());
        assert!(parse_args(["--scope", "teams", "--mine"], &env).is_err());
        assert!(parse_args(["--scope", "invalid"], &env).is_err());
        assert!(parse_args(["--visibility", "invalid"], &env).is_err());
        assert!(parse_args(["--owner", "../bad"], &env).is_err());
        assert!(parse_args(["--user", "../bad"], &env).is_err());
        assert!(parse_args(["--remote", "origin", "list"], &env).is_err());
        assert!(parse_args(["push", "--mine"], &env).is_err());
        assert!(parse_args(["push", "-q", "foo"], &env).is_err());
        assert!(parse_args(["push", "-r", "../bad"], &env).is_err());
        assert!(parse_args(["push", "../bad"], &env).is_err());
        assert!(parse_args(["push", "repo", "-bad-ref"], &env).is_err());
        assert!(parse_args(["push", "repo", "main", "extra"], &env).is_err());

        let empty_env = CliEnv::default();
        assert!(parse_args(Vec::<&str>::new(), &empty_env).is_err());
        assert!(parse_args(["--no-auth", "--mine"], &empty_env).is_err());
        assert!(parse_args(["--no-auth"], &empty_env).is_ok());
    }

    #[test]
    fn parse_grpc_authority_accepts_plain_http_and_grpc_schemes() {
        assert_eq!(
            parse_grpc_authority("127.0.0.1:8080").expect("plain"),
            "127.0.0.1:8080"
        );
        assert_eq!(
            parse_grpc_authority("http://localhost:8080/").expect("http"),
            "localhost:8080"
        );
        assert_eq!(
            parse_grpc_authority("grpc://[::1]:9000").expect("grpc ipv6"),
            "[::1]:9000"
        );
        assert!(parse_grpc_authority("").is_err());
        assert!(parse_grpc_authority("https://localhost:8080").is_err());
        assert!(parse_grpc_authority("localhost").is_err());
        assert!(parse_grpc_authority("localhost:0").is_err());
        assert!(parse_grpc_authority("[::1]:0").is_err());
        assert!(parse_grpc_authority("::1:8080").is_err());
        assert!(parse_grpc_authority("foo:bar:8080").is_err());
        assert!(parse_grpc_authority("[::1]]:8080").is_err());
        assert!(parse_grpc_authority("localhost:99999").is_err());
        assert!(parse_grpc_authority("http://localhost:8080/subpath").is_err());
    }

    #[test]
    fn resolve_ssh_key_path_discovers_default_ed25519_and_rsa_fallback() {
        let tmp = TempDir::new("ssh_discovery");
        let ssh_dir = tmp.path.join(".ssh");
        fs::create_dir_all(&ssh_dir).expect("create .ssh");

        assert!(resolve_ssh_key_path(None, None).is_err());
        assert!(resolve_ssh_key_path(None, Some(&tmp.path)).is_err());

        let rsa_path = ssh_dir.join("id_rsa");
        fs::write(&rsa_path, "dummy-rsa").expect("write id_rsa");
        assert_eq!(
            resolve_ssh_key_path(None, Some(&tmp.path)).expect("discover fallback id_rsa"),
            rsa_path
        );

        let ed25519_path = ssh_dir.join("id_ed25519");
        fs::write(&ed25519_path, "dummy-ed25519").expect("write id_ed25519");
        assert_eq!(
            resolve_ssh_key_path(None, Some(&tmp.path)).expect("prefer id_ed25519"),
            ed25519_path
        );

        assert_eq!(
            resolve_ssh_key_path(Some(&rsa_path), Some(&tmp.path)).expect("explicit key"),
            rsa_path
        );
        assert!(resolve_ssh_key_path(Some(&tmp.path.join("missing")), Some(&tmp.path)).is_err());
    }

    #[test]
    fn sign_bearer_token_and_encode_request_roundtrip() {
        let tmp = TempDir::new("token_sign");
        let key_path = tmp.path.join("id_ed25519");
        let keypair = ssh_key::private::Ed25519Keypair::from_seed(&[0x11; 32]);
        let priv_key = PrivateKey::from(keypair);
        let openssh = priv_key.to_openssh(LineEnding::LF).expect("to_openssh");
        fs::write(&key_path, openssh.as_bytes()).expect("write key");

        let token = sign_bearer_token_file(&key_path, "alice", 1_900_000_000).expect("sign file");
        let decoded = decode_bearer_token(&token).expect("decode token");
        assert_eq!(decoded.username, "alice");
        assert_eq!(decoded.exp_unix_secs, 1_900_000_000);

        assert!(sign_bearer_token_file(&key_path, "../bad", 1_900_000_000).is_err());
        assert!(sign_bearer_token(&priv_key, "../bad", 1_900_000_000).is_err());

        let bytes = encode_list_repositories_request("users", "alice", "private", "vault")
            .expect("encode request");
        let view = ListRepositoriesRequestView::from_bytes(&bytes).expect("decode request");
        assert_eq!(view.scope().unwrap(), "users");
        assert_eq!(view.owner().unwrap(), "alice");
        assert_eq!(view.visibility().unwrap(), "private");
        assert_eq!(view.query().unwrap(), "vault");
    }

    #[test]
    fn format_repositories_follows_rule_of_silence_when_empty() {
        assert_eq!(format_repositories(&[]), "");
        let records = vec![RepositoryRecord {
            scope: "users".to_owned(),
            owner: "alice".to_owned(),
            visibility: "private".to_owned(),
            name: "secret".to_owned(),
            ssh_url: "ssh://git.example.com/users/alice/private/secret.git".to_owned(),
        }];
        assert_eq!(
            format_repository_line(&records[0]),
            "alice/secret\tprivate\tusers\tssh://git.example.com/users/alice/private/secret.git"
        );
        assert_eq!(
            format_repositories(&records),
            "alice/secret\tprivate\tusers\tssh://git.example.com/users/alice/private/secret.git\n"
        );
    }
}
