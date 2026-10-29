use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use ro_git_proto::ro_git::v1::{
    worker_response, GetAuthStatusResponseView, ListRepositoriesRequestBuilder,
    ListRepositoriesResponseView, WorkerRequestBuilder, WorkerResponseView,
};
use ro_git_proto::{
    encode_bearer_token, format_token_payload, API_REPOSITORIES_PATH, SSH_SIG_NAMESPACE,
};
use ro_git_server::{spawn_worker_subprocess, GitServiceHandler, ServerConfig};
use roto::runtime::BackwardWriter;
use roto_grpc::http::{HttpMethod, HttpRequest};
use roto_grpc::RpcContext;
use ssh_key::{HashAlg, LineEnding, PrivateKey};

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct TempDirGuard {
    path: PathBuf,
    chmod_restore: Vec<PathBuf>,
}

impl TempDirGuard {
    fn new(name: &str) -> Self {
        let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "ro-git-worker-int-{name}-{}-{seq}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("create temp dir");
        Self {
            path,
            chmod_restore: Vec::new(),
        }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        for p in &self.chmod_restore {
            let _ = fs::set_permissions(p, fs::Permissions::from_mode(0o755));
        }
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[test]
fn git_worker_subprocess_executes_auth_status_and_repository_discovery() {
    let worker_bin = PathBuf::from(env!("CARGO_BIN_EXE_ro-git-server"));
    assert!(worker_bin.is_file(), "ro-git-server binary must exist");

    let mut temp = TempDirGuard::new("subprocess");
    let root = temp.path().to_path_buf();

    // Generate Ed25519 keypair for alice
    let kp = ssh_key::private::Ed25519Keypair::from_seed(&[0x55; 32]);
    let priv_key = PrivateKey::from(kp);
    let pub_openssh = priv_key.public_key().to_openssh().unwrap();

    let alice_dir = root.join("users/alice");
    fs::create_dir_all(&alice_dir).unwrap();
    let ak_path = alice_dir.join("authorized_keys");
    fs::write(&ak_path, format!("{pub_openssh}\n")).unwrap();
    fs::set_permissions(&ak_path, fs::Permissions::from_mode(0o600)).unwrap();

    // Provision repositories
    for rel in [
        "users/alice/public/notes.git",
        "users/alice/private/vault.git",
        "users/bob/public/tools.git",
        "users/bob/private/secret.git",
        "teams/platform/public/sdk.git",
        "teams/platform/private/deploy.git",
        "teams/security/private/audit.git",
    ] {
        fs::create_dir_all(root.join(rel)).unwrap();
    }
    fs::write(root.join("teams/platform/members"), "alice\n").unwrap();
    fs::write(root.join("teams/security/members"), "bob\n").unwrap();

    // Also make an unreadable private directory (mode 0000) to verify OS PermissionDenied skipping
    let unreadable_dir = root.join("users/charlie/public");
    fs::create_dir_all(unreadable_dir.join("hidden.git")).unwrap();
    fs::set_permissions(&unreadable_dir, fs::Permissions::from_mode(0o000)).unwrap();
    temp.chmod_restore.push(unreadable_dir);

    let now = 1_700_000_000;
    let max_ttl = 2_592_000;
    let payload = format_token_payload("alice", now + 3_600).unwrap();
    let sig = priv_key
        .sign(SSH_SIG_NAMESPACE, HashAlg::Sha512, payload.as_bytes())
        .unwrap();
    let pem = sig.to_pem(LineEnding::LF).unwrap();
    let token = encode_bearer_token(&payload, &pem).unwrap();

    // 1. Spawn `ro-git-server git-worker` subprocess for ListRepositories
    let mut req_buf = [0u8; 2048];
    let mut req_builder = WorkerRequestBuilder::new(&mut req_buf);
    req_builder
        .write_list_repositories(|_| {})
        .write_now_unix_secs(now)
        .write_max_token_ttl_secs(max_ttl)
        .write_ssh_host("git.corp.local:2222")
        .write_root_dir(&root.to_string_lossy())
        .write_token(&token);
    let req_bytes = req_builder.finish().unwrap();

    let resp_bytes = spawn_worker_subprocess(&worker_bin, req_bytes).expect("spawn git-worker");
    let resp_view = WorkerResponseView::from_bytes(&resp_bytes).unwrap();
    assert_eq!(resp_view.status_code().unwrap(), 0);

    match resp_view.result().unwrap() {
        Some(worker_response::Result::ListRepositories(list_view)) => {
            assert_eq!(list_view.authenticated_user().unwrap(), "alice");
            assert_eq!(list_view.ssh_host().unwrap(), "git.corp.local:2222");
            let paths: Vec<_> = list_view
                .repositories()
                .map(|r| r.unwrap().canonical_path().unwrap())
                .collect();
            assert_eq!(
                paths,
                vec![
                    "/teams/platform/private/deploy.git",
                    "/teams/platform/public/sdk.git",
                    "/users/alice/private/vault.git",
                    "/users/alice/public/notes.git",
                    "/users/bob/public/tools.git",
                ]
            );
        }
        other => panic!("expected ListRepositories, got {other:?}"),
    }

    // 2. Verify end-to-end GitServiceHandler calls using the real worker subprocess
    std::env::set_var("RO_GIT_WORKER_BIN", &worker_bin);
    let live_exp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3_600;
    let live_payload = format_token_payload("alice", live_exp).unwrap();
    let live_sig = priv_key
        .sign(SSH_SIG_NAMESPACE, HashAlg::Sha512, live_payload.as_bytes())
        .unwrap();
    let live_pem = live_sig.to_pem(LineEnding::LF).unwrap();
    let live_token = encode_bearer_token(&live_payload, &live_pem).unwrap();
    let bearer_header = format!("Bearer {live_token}");

    let server = GitServiceHandler::new(ServerConfig {
        root_dir: root.to_string_lossy().into_owned(),
        ssh_host: String::from("git.corp.local:2222"),
        ..ServerConfig::default()
    })
    .into_server();

    let mut ctx = RpcContext::<roto_grpc::FixedMetadata>::new();
    ctx.request
        .insert("authorization", &bearer_header)
        .expect("insert authorization header");
    let mut scratch = [0u8; 2048];
    let mut out_buf = [0u8; 4096];

    let mut meta = ctx.metadata();
    let mut writer = BackwardWriter::new(&mut out_buf);
    server
        .call_unary(&mut meta, "GetAuthStatus", &[], &mut writer)
        .unwrap();
    let lpm = writer.finish().unwrap();
    let auth_view = GetAuthStatusResponseView::from_bytes(&lpm[5..]).unwrap();
    assert!(auth_view.authenticated().unwrap());
    assert_eq!(auth_view.username().unwrap(), "alice");

    let mut filter_buf = [0u8; 256];
    let mut filter_builder = ListRepositoriesRequestBuilder::new(&mut filter_buf);
    filter_builder.write_query("platform");
    let filter_bytes = filter_builder.finish().unwrap();

    let mut meta = ctx.metadata();
    let mut writer = BackwardWriter::new(&mut out_buf);
    server
        .call_unary(&mut meta, "ListRepositories", filter_bytes, &mut writer)
        .unwrap();
    let lpm = writer.finish().unwrap();
    let repos_view = ListRepositoriesResponseView::from_bytes(&lpm[5..]).unwrap();
    let filtered_paths: Vec<_> = repos_view
        .repositories()
        .map(|r| r.unwrap().canonical_path().unwrap())
        .collect();
    assert_eq!(
        filtered_paths,
        vec![
            "/teams/platform/private/deploy.git",
            "/teams/platform/public/sdk.git",
        ]
    );

    // 3. Anonymous HTTP request via call_http returns only public repositories
    let anon_uri = format!("{API_REPOSITORIES_PATH}?visibility=public");
    let anon_http_req = HttpRequest::from_uri(HttpMethod::Get, &anon_uri, None, &[]);
    let mut writer = BackwardWriter::new(&mut out_buf);
    let anon_http_resp = server
        .call_http(&anon_http_req, &mut scratch, &mut writer)
        .unwrap()
        .unwrap();
    assert_eq!(anon_http_resp.status_code, 200);
    let anon_view = ListRepositoriesResponseView::from_bytes(anon_http_resp.body).unwrap();
    assert_eq!(anon_view.authenticated_user().unwrap(), "");
    let anon_paths: Vec<_> = anon_view
        .repositories()
        .map(|r| r.unwrap().canonical_path().unwrap())
        .collect();
    assert_eq!(
        anon_paths,
        vec![
            "/teams/platform/public/sdk.git",
            "/users/alice/public/notes.git",
            "/users/bob/public/tools.git",
        ]
    );

    // 4. Populate `/teams/platform/private/deploy.git` and verify all 5 object reader commands via git-worker subprocess
    let deploy_bare = root.join("teams/platform/private/deploy.git");
    let _ = fs::remove_dir_all(&deploy_bare);
    fs::create_dir_all(&deploy_bare).unwrap();
    let out = std::process::Command::new("git")
        .current_dir(&deploy_bare)
        .args(["init", "--bare", "--initial-branch=main"])
        .output()
        .unwrap();
    assert!(out.status.success());

    let work = root.join("deploy-work");
    fs::create_dir_all(work.join("charts")).unwrap();
    let run_git = |args: &[&str]| {
        let out = std::process::Command::new("git")
            .current_dir(&work)
            .args(args)
            .env("GIT_AUTHOR_NAME", "Alice")
            .env("GIT_AUTHOR_EMAIL", "alice@corp.local")
            .env("GIT_AUTHOR_DATE", "1700001000 +0000")
            .env("GIT_COMMITTER_NAME", "Alice")
            .env("GIT_COMMITTER_EMAIL", "alice@corp.local")
            .env("GIT_COMMITTER_DATE", "1700001000 +0000")
            .output()
            .unwrap();
        assert!(out.status.success(), "{:?}", String::from_utf8_lossy(&out.stderr));
    };
    run_git(&["init", "--initial-branch=main"]);
    fs::write(work.join("README.md"), "# Deploy\n").unwrap();
    fs::write(work.join("charts/values.yaml"), "replicas: 3\n").unwrap();
    run_git(&["add", "."]);
    run_git(&["commit", "-m", "Add deploy charts"]);
    run_git(&["tag", "v1.0.0"]);
    run_git(&["remote", "add", "origin", &deploy_bare.to_string_lossy()]);
    run_git(&["push", "origin", "main", "--tags"]);

    // 4a. GetRepository via git-worker subprocess
    let mut req_buf = [0u8; 2048];
    let mut req_builder = WorkerRequestBuilder::new(&mut req_buf);
    req_builder
        .write_get_repository(|gr| {
            gr.write_revision("")
                .write_name("deploy")
                .write_visibility("private")
                .write_owner("platform")
                .write_scope("teams");
        })
        .write_now_unix_secs(now)
        .write_max_token_ttl_secs(max_ttl)
        .write_ssh_host("git.corp.local:2222")
        .write_root_dir(&root.to_string_lossy())
        .write_token(&token);
    let resp_bytes =
        spawn_worker_subprocess(&worker_bin, req_builder.finish().unwrap()).unwrap();
    let resp_view = WorkerResponseView::from_bytes(&resp_bytes).unwrap();
    assert_eq!(resp_view.status_code().unwrap(), 0);
    let head_oid = match resp_view.result().unwrap() {
        Some(worker_response::Result::GetRepository(gr)) => {
            assert_eq!(gr.head_ref().unwrap(), "main");
            assert_eq!(gr.resolved_revision().unwrap(), "main");
            assert_eq!(gr.branches().count(), 1);
            assert_eq!(gr.tags().count(), 1);
            assert_eq!(gr.entries().count(), 2);
            gr.head_oid().unwrap().to_owned()
        }
        other => panic!("expected GetRepository, got {other:?}"),
    };

    // 4b. GetTree via git-worker subprocess
    let mut req_builder = WorkerRequestBuilder::new(&mut req_buf);
    req_builder
        .write_get_tree(|gt| {
            gt.write_path("charts")
                .write_revision("v1.0.0")
                .write_name("deploy")
                .write_visibility("private")
                .write_owner("platform")
                .write_scope("teams");
        })
        .write_now_unix_secs(now)
        .write_max_token_ttl_secs(max_ttl)
        .write_ssh_host("git.corp.local:2222")
        .write_root_dir(&root.to_string_lossy())
        .write_token(&token);
    let resp_bytes =
        spawn_worker_subprocess(&worker_bin, req_builder.finish().unwrap()).unwrap();
    let resp_view = WorkerResponseView::from_bytes(&resp_bytes).unwrap();
    assert_eq!(resp_view.status_code().unwrap(), 0);
    match resp_view.result().unwrap() {
        Some(worker_response::Result::GetTree(gt)) => {
            assert_eq!(gt.path().unwrap(), "charts");
            let entry = gt.entries().next().unwrap().unwrap();
            assert_eq!(entry.name().unwrap(), "values.yaml");
            assert_eq!(entry.path().unwrap(), "charts/values.yaml");
        }
        other => panic!("expected GetTree, got {other:?}"),
    }

    // 4c. GetBlob via git-worker subprocess
    let mut req_builder = WorkerRequestBuilder::new(&mut req_buf);
    req_builder
        .write_get_blob(|gb| {
            gb.write_path("charts/values.yaml")
                .write_revision("main")
                .write_name("deploy")
                .write_visibility("private")
                .write_owner("platform")
                .write_scope("teams");
        })
        .write_now_unix_secs(now)
        .write_max_token_ttl_secs(max_ttl)
        .write_ssh_host("git.corp.local:2222")
        .write_root_dir(&root.to_string_lossy())
        .write_token(&token);
    let resp_bytes =
        spawn_worker_subprocess(&worker_bin, req_builder.finish().unwrap()).unwrap();
    let resp_view = WorkerResponseView::from_bytes(&resp_bytes).unwrap();
    assert_eq!(resp_view.status_code().unwrap(), 0);
    match resp_view.result().unwrap() {
        Some(worker_response::Result::GetBlob(gb)) => {
            assert_eq!(gb.content().unwrap(), b"replicas: 3\n");
            assert!(!gb.is_binary().unwrap());
        }
        other => panic!("expected GetBlob, got {other:?}"),
    }

    // 4d. ListCommits & GetCommit via git-worker subprocess
    let mut req_builder = WorkerRequestBuilder::new(&mut req_buf);
    req_builder
        .write_list_commits(|lc| {
            lc.write_limit(10)
                .write_revision("main")
                .write_name("deploy")
                .write_visibility("private")
                .write_owner("platform")
                .write_scope("teams");
        })
        .write_now_unix_secs(now)
        .write_max_token_ttl_secs(max_ttl)
        .write_ssh_host("git.corp.local:2222")
        .write_root_dir(&root.to_string_lossy())
        .write_token(&token);
    let resp_bytes =
        spawn_worker_subprocess(&worker_bin, req_builder.finish().unwrap()).unwrap();
    let resp_view = WorkerResponseView::from_bytes(&resp_bytes).unwrap();
    assert_eq!(resp_view.status_code().unwrap(), 0);
    match resp_view.result().unwrap() {
        Some(worker_response::Result::ListCommits(lc)) => {
            assert_eq!(lc.commits().count(), 1);
            assert!(!lc.has_more().unwrap());
        }
        other => panic!("expected ListCommits, got {other:?}"),
    }

    let mut req_builder = WorkerRequestBuilder::new(&mut req_buf);
    req_builder
        .write_get_commit(|gc| {
            gc.write_revision(&head_oid)
                .write_name("deploy")
                .write_visibility("private")
                .write_owner("platform")
                .write_scope("teams");
        })
        .write_now_unix_secs(now)
        .write_max_token_ttl_secs(max_ttl)
        .write_ssh_host("git.corp.local:2222")
        .write_root_dir(&root.to_string_lossy())
        .write_token(&token);
    let resp_bytes =
        spawn_worker_subprocess(&worker_bin, req_builder.finish().unwrap()).unwrap();
    let resp_view = WorkerResponseView::from_bytes(&resp_bytes).unwrap();
    assert_eq!(resp_view.status_code().unwrap(), 0);
    match resp_view.result().unwrap() {
        Some(worker_response::Result::GetCommit(gc)) => {
            assert_eq!(gc.commit().unwrap().unwrap().oid().unwrap(), head_oid);
            assert_eq!(gc.files().count(), 2);
            assert_eq!(gc.total_additions().unwrap(), 2);
        }
        other => panic!("expected GetCommit, got {other:?}"),
    }
}
