use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use ro_git_proto::grpc::ro_git::v1::git_service::GitServiceClient;
use ro_git_proto::ro_git::v1::{
    GetAuthStatusRequestBuilder, GetAuthStatusResponseView, ListRepositoriesRequestBuilder,
    ListRepositoriesResponseView,
};
use ro_git_proto::{
    encode_bearer_token, format_token_payload, API_AUTH_STATUS_PATH, API_REPOSITORIES_PATH,
    SSH_SIG_NAMESPACE,
};
use ro_git_server::{start_server, ServerConfig};
use roto_grpc::{DynamicMetadata, GrpcClient, GrpcCode, StdClientTransport};
use ssh_key::{HashAlg, LineEnding, PrivateKey};

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(prefix: &str) -> Self {
        let seq = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "ro-git-int-{prefix}-{}-{seq}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("create temp dir");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn current_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn test_ed25519_keypair(seed_byte: u8) -> (PrivateKey, String) {
    let seed = [seed_byte; 32];
    let keypair = ssh_key::private::Ed25519Keypair::from_seed(&seed);
    let priv_key = PrivateKey::from(keypair);
    let pub_openssh = priv_key
        .public_key()
        .to_openssh()
        .expect("serialize public key");
    (priv_key, pub_openssh)
}

fn make_bearer_token(priv_key: &PrivateKey, username: &str, exp_secs: u64) -> String {
    let payload = format_token_payload(username, exp_secs).expect("format token payload");
    let sig = priv_key
        .sign(SSH_SIG_NAMESPACE, HashAlg::Sha512, payload.as_bytes())
        .expect("sign payload");
    let pem = sig.to_pem(LineEnding::LF).expect("encode SSHSIG PEM");
    let tok = encode_bearer_token(&payload, &pem).expect("encode bearer token");
    format!("Bearer {tok}")
}

fn create_bare_repo(root: &Path, scope: &str, owner: &str, visibility: &str, name: &str) {
    let repo_dir = root
        .join(scope)
        .join(owner)
        .join(visibility)
        .join(format!("{name}.git"));
    fs::create_dir_all(repo_dir.join("objects")).expect("create objects dir");
    fs::create_dir_all(repo_dir.join("refs")).expect("create refs dir");
    fs::write(repo_dir.join("HEAD"), "ref: refs/heads/main\n").expect("write HEAD");
}

fn setup_fixture_root() -> (TempDir, PrivateKey) {
    let temp = TempDir::new("root");
    let root = temp.path();

    // Users: alice (member of core), bob (member of ops)
    fs::create_dir_all(root.join("etc")).expect("create etc");
    fs::write(
        root.join("etc/passwd"),
        "root:x:0:0:root:/root:/bin/sh\n\
         nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n\
         alice:x:1001:1001:Alice:/users/alice:/bin/sh\n\
         bob:x:1002:1002:Bob:/users/bob:/bin/sh\n",
    )
    .expect("write passwd");
    fs::write(
        root.join("etc/group"),
        "root:x:0:\n\
         nogroup:x:65534:\n\
         alice:x:1001:\n\
         bob:x:1002:\n\
         team-core:x:2001:alice\n\
         team-ops:x:2002:bob\n",
    )
    .expect("write group");

    let (alice_priv, alice_pub) = test_ed25519_keypair(0x5A);
    let user_dir = root.join("users/alice");
    fs::create_dir_all(&user_dir).expect("create alice user dir");
    let ak_path = user_dir.join("authorized_keys");
    fs::write(&ak_path, format!("{alice_pub}\n")).expect("write authorized_keys");
    fs::set_permissions(&ak_path, fs::Permissions::from_mode(0o600)).expect("chmod 600 ak");

    fs::create_dir_all(root.join("teams/core")).expect("create core team dir");
    fs::write(root.join("teams/core/members"), "alice\n").expect("write core members");
    fs::create_dir_all(root.join("teams/ops")).expect("create ops team dir");
    fs::write(root.join("teams/ops/members"), "bob\n").expect("write ops members");

    // Repositories
    create_bare_repo(root, "users", "alice", "public", "dotfiles");
    create_bare_repo(root, "users", "alice", "private", "notes");
    create_bare_repo(root, "users", "bob", "public", "blog");
    create_bare_repo(root, "users", "bob", "private", "vault");
    create_bare_repo(root, "teams", "core", "public", "ro-git");
    create_bare_repo(root, "teams", "core", "private", "roadmap");
    create_bare_repo(root, "teams", "ops", "private", "infra");

    (temp, alice_priv)
}

fn setup_static_dir() -> TempDir {
    let temp = TempDir::new("static");
    let dir = temp.path();

    fs::write(
        dir.join("index.html"),
        "<!DOCTYPE html><html><body>ro-git SPA</body></html>",
    )
    .expect("write index.html");
    fs::write(dir.join("ro-git-ui_bg.wasm"), b"\x00asm\x01\x00\x00\x00mockwasm")
        .expect("write wasm");
    fs::write(dir.join("ro-git-ui.js"), "console.log('ro-git-ui');\n").expect("write js");
    fs::write(dir.join("style.css"), "body { margin: 0; }\n").expect("write css");
    fs::write(dir.join("logo.svg"), "<svg xmlns=\"http://www.w3.org/2000/svg\"/>")
        .expect("write svg");

    // Symlinked file and directory inside static_dir (must be rejected)
    let outside_secret = std::env::temp_dir().join(format!("ro-git-secret-{}", std::process::id()));
    fs::write(&outside_secret, "top-secret").expect("write secret");
    let _ = symlink(&outside_secret, dir.join("secret-link.html"));
    let _ = fs::remove_file(&outside_secret);

    fs::create_dir_all(dir.join("real-sub")).expect("create real-sub");
    fs::write(dir.join("real-sub/inside.js"), "// inside").expect("write inside.js");
    let _ = symlink(dir.join("real-sub"), dir.join("symlink-sub"));

    temp
}

struct HttpRawResponse {
    status_code: u16,
    content_type: String,
    content_length: usize,
    body: Vec<u8>,
}

fn send_http1_request(
    addr: SocketAddr,
    method: &str,
    target: &str,
    headers: &[(&str, &str)],
) -> HttpRawResponse {
    let mut stream = TcpStream::connect(addr).expect("connect HTTP/1.1 to server");
    let mut req = format!("{method} {target} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n");
    for &(k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    stream.write_all(req.as_bytes()).expect("write HTTP/1.1 request");
    stream.flush().expect("flush HTTP/1.1 request");

    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).expect("read HTTP/1.1 response");

    let header_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("HTTP response header delimiter")
        + 4;
    let header_str = std::str::from_utf8(&raw[..header_end]).expect("UTF-8 HTTP response headers");
    let body = raw[header_end..].to_vec();

    let mut lines = header_str.split("\r\n");
    let status_line = lines.next().expect("status line");
    let status_code = status_line
        .split_whitespace()
        .nth(1)
        .expect("status code token")
        .parse::<u16>()
        .expect("numeric status code");

    let mut content_type = String::new();
    let mut content_length = 0usize;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let k = k.trim();
            let v = v.trim();
            if k.eq_ignore_ascii_case("content-type") {
                content_type = v.to_owned();
            } else if k.eq_ignore_ascii_case("content-length") {
                content_length = v.parse().unwrap_or(0);
            }
        }
    }

    HttpRawResponse {
        status_code,
        content_type,
        content_length,
        body,
    }
}

#[test]
fn end_to_end_grpc_and_http_anonymous_bearer_and_proxy_auth() {
    let (root_dir, alice_priv) = setup_fixture_root();
    let static_dir = setup_static_dir();

    let server = start_server(ServerConfig {
        listen_addr: String::from("127.0.0.1:0"),
        root_dir: root_dir.path().to_string_lossy().into_owned(),
        ssh_host: String::from("git.example.com"),
        static_dir: static_dir.path().to_string_lossy().into_owned(),
        max_token_ttl_secs: 2_592_000,
        nobody_uid: 65_534,
        dev_user: None,
    })
    .expect("start_server on 127.0.0.1:0");
    let addr = server.local_addr();

    // =========================================================================
    // 1. Real TCP gRPC client over HTTP/2 (`StdClientTransport` + `DynamicMetadata`)
    // =========================================================================
    let tcp = TcpStream::connect(addr).expect("connect gRPC TCP stream");
    let _ = tcp.set_nodelay(true);
    let mut tx_buf = vec![0u8; 65_536];
    let mut call_buf = vec![0u8; 65_536];
    let grpc_client = GrpcClient::<4, 16_384, DynamicMetadata>::with_metadata_store(
        "http",
        "git.example.com",
        &mut tx_buf,
    );
    let transport = StdClientTransport::<TcpStream, 4, 16_384, 4096, DynamicMetadata>::with_metadata_store_and_io_buf(
        tcp,
        grpc_client,
        &mut call_buf,
    );
    let mut client = GitServiceClient::new(transport);

    // 1a. Anonymous gRPC GetAuthStatus & ListRepositories
    let mut req_buf = [0u8; 128];
    let req_bytes = GetAuthStatusRequestBuilder::new(&mut req_buf)
        .finish()
        .unwrap();
    let auth_view = client
        .get_auth_status(req_bytes)
        .expect("anonymous gRPC GetAuthStatus");
    assert!(!auth_view.authenticated().unwrap());
    assert_eq!(auth_view.username().unwrap_or(""), "");
    assert_eq!(auth_view.ssh_host().unwrap(), "git.example.com");

    let req_bytes = ListRepositoriesRequestBuilder::new(&mut req_buf)
        .finish()
        .unwrap();
    let list_view = client
        .list_repositories(req_bytes)
        .expect("anonymous gRPC ListRepositories");
    assert_eq!(list_view.authenticated_user().unwrap_or(""), "");
    let anon_paths: Vec<String> = list_view
        .repositories()
        .map(|r| r.unwrap().canonical_path().unwrap().to_owned())
        .collect();
    assert_eq!(
        anon_paths,
        vec![
            "/teams/core/public/ro-git.git",
            "/users/alice/public/dotfiles.git",
            "/users/bob/public/blog.git",
        ]
    );

    // 1b. Authenticated gRPC with Authorization: Bearer <token>
    let bearer_alice = make_bearer_token(&alice_priv, "alice", current_unix_secs() + 3_600);
    client
        .insert_metadata("authorization", &bearer_alice)
        .unwrap();
    let auth_view = client
        .get_auth_status(req_bytes)
        .expect("authenticated gRPC GetAuthStatus");
    assert!(auth_view.authenticated().unwrap());
    assert_eq!(auth_view.username().unwrap(), "alice");
    assert_eq!(auth_view.ssh_host().unwrap(), "git.example.com");

    client
        .insert_metadata("authorization", &bearer_alice)
        .unwrap();
    let list_view = client
        .list_repositories(req_bytes)
        .expect("authenticated gRPC ListRepositories");
    assert_eq!(list_view.authenticated_user().unwrap(), "alice");
    let alice_repos: Vec<(String, String, String)> = list_view
        .repositories()
        .map(|r| {
            let v = r.unwrap();
            (
                v.canonical_path().unwrap().to_owned(),
                v.ssh_url().unwrap().to_owned(),
                v.clone_command().unwrap().to_owned(),
            )
        })
        .collect();
    let alice_paths: Vec<&str> = alice_repos.iter().map(|(p, _, _)| p.as_str()).collect();
    assert_eq!(
        alice_paths,
        vec![
            "/teams/core/private/roadmap.git",
            "/teams/core/public/ro-git.git",
            "/users/alice/private/notes.git",
            "/users/alice/public/dotfiles.git",
            "/users/bob/public/blog.git",
        ]
    );
    assert_eq!(
        alice_repos[0].1,
        "ssh://git.example.com/teams/core/private/roadmap.git"
    );
    assert_eq!(
        alice_repos[0].2,
        "git clone ssh://alice@git.example.com/teams/core/private/roadmap.git"
    );

    // 1c. Authenticated gRPC with X-Forwarded-User and Remote-User headers
    client.insert_metadata("x-forwarded-user", "bob").unwrap();
    let bob_view = client
        .list_repositories(req_bytes)
        .expect("X-Forwarded-User gRPC ListRepositories");
    assert_eq!(bob_view.authenticated_user().unwrap(), "bob");
    let bob_paths: Vec<String> = bob_view
        .repositories()
        .map(|r| r.unwrap().canonical_path().unwrap().to_owned())
        .collect();
    assert_eq!(
        bob_paths,
        vec![
            "/teams/core/public/ro-git.git",
            "/teams/ops/private/infra.git",
            "/users/alice/public/dotfiles.git",
            "/users/bob/private/vault.git",
            "/users/bob/public/blog.git",
        ]
    );

    client.insert_metadata("remote-user", "alice").unwrap();
    let remote_view = client
        .get_auth_status(req_bytes)
        .expect("Remote-User gRPC GetAuthStatus");
    assert!(remote_view.authenticated().unwrap());
    assert_eq!(remote_view.username().unwrap(), "alice");

    // 1d. Invalid Bearer token over gRPC returns Unauthenticated
    client
        .insert_metadata("authorization", "Bearer tampered.token")
        .unwrap();
    let err = client
        .get_auth_status(req_bytes)
        .expect_err("tampered bearer token must fail");
    assert_eq!(err.code, GrpcCode::Unauthenticated);

    drop(client);

    // =========================================================================
    // 2. Real TCP HTTP/1.1 API calls (/api/v1/auth/status & /api/v1/repositories)
    // =========================================================================
    // 2a. Anonymous HTTP protobuf response
    let resp = send_http1_request(addr, "GET", API_AUTH_STATUS_PATH, &[]);
    assert_eq!(resp.status_code, 200);
    assert_eq!(resp.content_type, "application/x-protobuf");
    let view = GetAuthStatusResponseView::from_bytes(&resp.body).unwrap();
    assert!(!view.authenticated().unwrap());

    let resp = send_http1_request(addr, "GET", API_REPOSITORIES_PATH, &[]);
    assert_eq!(resp.status_code, 200);
    assert_eq!(resp.content_type, "application/x-protobuf");
    let view = ListRepositoriesResponseView::from_bytes(&resp.body).unwrap();
    assert_eq!(view.repositories().count(), 3);

    // 2b. Authenticated HTTP with Authorization: Bearer <token> (both Protobuf and JSON)
    let resp = send_http1_request(
        addr,
        "GET",
        API_AUTH_STATUS_PATH,
        &[("Authorization", &bearer_alice)],
    );
    assert_eq!(resp.status_code, 200);
    let view = GetAuthStatusResponseView::from_bytes(&resp.body).unwrap();
    assert!(view.authenticated().unwrap());
    assert_eq!(view.username().unwrap(), "alice");

    let json_resp = send_http1_request(
        addr,
        "GET",
        API_AUTH_STATUS_PATH,
        &[
            ("Authorization", &bearer_alice),
            ("Accept", "application/json"),
        ],
    );
    assert_eq!(json_resp.status_code, 200);
    assert_eq!(json_resp.content_type, "application/json; charset=utf-8");
    let json_str = std::str::from_utf8(&json_resp.body).unwrap();
    assert!(json_str.contains("\"authenticated\":true"));
    assert!(json_str.contains("\"username\":\"alice\""));
    assert!(json_str.contains("\"ssh_host\":\"git.example.com\""));

    // Filtered HTTP repositories query with Bearer token
    let filtered_resp = send_http1_request(
        addr,
        "GET",
        "/api/v1/repositories?scope=teams&owner=core&visibility=private&query=road",
        &[("Authorization", &bearer_alice)],
    );
    assert_eq!(filtered_resp.status_code, 200);
    let view = ListRepositoriesResponseView::from_bytes(&filtered_resp.body).unwrap();
    assert_eq!(view.repositories().count(), 1);
    let repo = view.repositories().next().unwrap().unwrap();
    assert_eq!(repo.canonical_path().unwrap(), "/teams/core/private/roadmap.git");

    // 2c. Authenticated HTTP with X-Forwarded-User and Remote-User
    let xfu_resp = send_http1_request(
        addr,
        "GET",
        API_REPOSITORIES_PATH,
        &[("X-Forwarded-User", "bob")],
    );
    assert_eq!(xfu_resp.status_code, 200);
    let xfu_view = ListRepositoriesResponseView::from_bytes(&xfu_resp.body).unwrap();
    assert_eq!(xfu_view.authenticated_user().unwrap(), "bob");
    assert_eq!(xfu_view.repositories().count(), 5);

    let ru_resp = send_http1_request(
        addr,
        "GET",
        API_AUTH_STATUS_PATH,
        &[("Remote-User", "bob")],
    );
    assert_eq!(ru_resp.status_code, 200);
    let ru_view = GetAuthStatusResponseView::from_bytes(&ru_resp.body).unwrap();
    assert!(ru_view.authenticated().unwrap());
    assert_eq!(ru_view.username().unwrap(), "bob");

    // 2d. Invalid Bearer token over HTTP returns 401
    let bad_resp = send_http1_request(
        addr,
        "GET",
        API_AUTH_STATUS_PATH,
        &[("Authorization", "Bearer bad.token")],
    );
    assert_eq!(bad_resp.status_code, 401);

    // 2e. Unknown /api/... path returns 404 (never SPA index.html)
    let unknown_api = send_http1_request(addr, "GET", "/api/v1/nonexistent", &[]);
    assert_eq!(unknown_api.status_code, 404);

    // =========================================================================
    // 3. Static Asset Hosting & Security Checks
    // =========================================================================
    // 3a. Root `/` and `/index.html`
    let root_resp = send_http1_request(addr, "GET", "/", &[]);
    assert_eq!(root_resp.status_code, 200);
    assert_eq!(root_resp.content_type, "text/html; charset=utf-8");
    assert_eq!(
        root_resp.body,
        b"<!DOCTYPE html><html><body>ro-git SPA</body></html>"
    );

    // 3b. `.wasm`, `.js`, `.css`, `.svg` MIME types
    let wasm_resp = send_http1_request(addr, "GET", "/ro-git-ui_bg.wasm", &[]);
    assert_eq!(wasm_resp.status_code, 200);
    assert_eq!(wasm_resp.content_type, "application/wasm");
    assert_eq!(wasm_resp.body, b"\x00asm\x01\x00\x00\x00mockwasm");

    let head_wasm = send_http1_request(addr, "HEAD", "/ro-git-ui_bg.wasm", &[]);
    assert_eq!(head_wasm.status_code, 200);
    assert_eq!(head_wasm.content_type, "application/wasm");
    assert_eq!(head_wasm.content_length, b"\x00asm\x01\x00\x00\x00mockwasm".len());
    assert!(head_wasm.body.is_empty());

    let js_resp = send_http1_request(addr, "GET", "/ro-git-ui.js", &[]);
    assert_eq!(js_resp.status_code, 200);
    assert_eq!(js_resp.content_type, "application/javascript; charset=utf-8");
    assert_eq!(js_resp.body, b"console.log('ro-git-ui');\n");

    let css_resp = send_http1_request(addr, "GET", "/style.css", &[]);
    assert_eq!(css_resp.status_code, 200);
    assert_eq!(css_resp.content_type, "text/css; charset=utf-8");

    let svg_resp = send_http1_request(addr, "GET", "/logo.svg", &[]);
    assert_eq!(svg_resp.status_code, 200);
    assert_eq!(svg_resp.content_type, "image/svg+xml");

    // 3c. SPA fallback for unknown non-API client routes
    let spa_resp = send_http1_request(addr, "GET", "/users/alice/repositories", &[]);
    assert_eq!(spa_resp.status_code, 200);
    assert_eq!(spa_resp.content_type, "text/html; charset=utf-8");
    assert_eq!(
        spa_resp.body,
        b"<!DOCTYPE html><html><body>ro-git SPA</body></html>"
    );

    // 3d. Path traversal rejection
    for traversal_path in [
        "/../etc/passwd",
        "/%2e%2e/etc/passwd",
        "/real-sub/../../etc/passwd",
    ] {
        let trav_resp = send_http1_request(addr, "GET", traversal_path, &[]);
        assert_eq!(
            trav_resp.status_code, 403,
            "traversal path {traversal_path} must be rejected with 403"
        );
    }

    // 3e. Symlink rejection (both direct symlink file and symlinked subdirectory)
    for symlink_path in ["/secret-link.html", "/symlink-sub/inside.js"] {
        let sym_resp = send_http1_request(addr, "GET", symlink_path, &[]);
        assert_eq!(
            sym_resp.status_code, 403,
            "symlink path {symlink_path} must be rejected with 403"
        );
    }

    server.shutdown();
}

#[test]
fn end_to_end_dev_user_fallback_over_grpc_and_http() {
    let (root_dir, _alice_priv) = setup_fixture_root();
    let static_dir = setup_static_dir();

    let server = start_server(ServerConfig {
        listen_addr: String::from("127.0.0.1:0"),
        root_dir: root_dir.path().to_string_lossy().into_owned(),
        ssh_host: String::from("git.example.com"),
        static_dir: static_dir.path().to_string_lossy().into_owned(),
        max_token_ttl_secs: 2_592_000,
        nobody_uid: 65_534,
        dev_user: Some(String::from("alice")),
    })
    .expect("start_server with dev_user");
    let addr = server.local_addr();

    // HTTP/1.1 request without headers falls back to RO_GIT_DEV_USER ("alice")
    let resp = send_http1_request(addr, "GET", API_AUTH_STATUS_PATH, &[]);
    assert_eq!(resp.status_code, 200);
    let view = GetAuthStatusResponseView::from_bytes(&resp.body).unwrap();
    assert!(view.authenticated().unwrap());
    assert_eq!(view.username().unwrap(), "alice");

    let repos_resp = send_http1_request(addr, "GET", API_REPOSITORIES_PATH, &[]);
    assert_eq!(repos_resp.status_code, 200);
    let repos_view = ListRepositoriesResponseView::from_bytes(&repos_resp.body).unwrap();
    assert_eq!(repos_view.authenticated_user().unwrap(), "alice");
    assert_eq!(repos_view.repositories().count(), 5);

    server.shutdown();
}
