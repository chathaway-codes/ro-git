#![forbid(unsafe_code)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use ro_git_cli::{run_with_env, CliEnv};
use ro_git_server::{start_server, RunningServer, ServerConfig};
use ssh_key::{LineEnding, PrivateKey};

static TEST_COUNTER: AtomicU64 = AtomicU64::new(1);

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(prefix: &str) -> Self {
        let id = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "ro_git_cli_integ_{}_{}_{}",
            prefix,
            std::process::id(),
            id
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("Failed to create temp dir");
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

fn test_ed25519_key(seed_byte: u8) -> PrivateKey {
    let seed = [seed_byte; 32];
    let keypair = ssh_key::private::Ed25519Keypair::from_seed(&seed);
    PrivateKey::from(keypair)
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

fn write_authorized_key(root: &Path, username: &str, priv_key: &PrivateKey) {
    let user_dir = root.join("users").join(username);
    fs::create_dir_all(&user_dir).expect("Failed to create user dir");
    let pub_openssh = priv_key
        .public_key()
        .to_openssh()
        .expect("Failed to format public key");
    let ak_path = user_dir.join("authorized_keys");
    fs::write(&ak_path, format!("{pub_openssh}\n")).expect("Failed to write authorized_keys");
    fs::set_permissions(&ak_path, fs::Permissions::from_mode(0o600))
        .expect("Failed to chmod authorized_keys");
}

fn write_default_user_ssh_key(home: &Path, priv_key: &PrivateKey) -> PathBuf {
    let ssh_dir = home.join(".ssh");
    fs::create_dir_all(&ssh_dir).expect("Failed to create home .ssh dir");
    let key_path = ssh_dir.join("id_ed25519");
    let openssh_pem = priv_key
        .to_openssh(LineEnding::LF)
        .expect("Failed to serialize OpenSSH private key");
    fs::write(&key_path, openssh_pem.as_bytes()).expect("Failed to write id_ed25519");
    key_path
}

fn start_test_server(root: &Path) -> RunningServer {
    let cfg = ServerConfig {
        listen_addr: String::from("127.0.0.1:0"),
        root_dir: root.to_string_lossy().into_owned(),
        ssh_host: String::from("git.example.test"),
        https_host: String::from("git.example.test"),
        static_dir: String::new(),
        max_token_ttl_secs: 3600,
        nobody_uid: 65_534,
        dev_user: None,
    };
    start_server(cfg).expect("Failed to start test server")
}

fn run_git_cmd(cwd: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .current_dir(cwd)
        .args(args)
        .output()
        .expect("Failed to spawn git");
    assert!(
        out.status.success(),
        "git {:?} failed: {}",
        args,
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

#[test]
fn cli_lists_searches_and_shortcuts_user_repos_over_grpc_with_default_ssh_key() {
    let tmp = TempDir::new("e2e");
    let root = tmp.path().join("srv");
    let alice_home = tmp.path().join("home_alice");

    let alice_key = test_ed25519_key(0x42);
    write_authorized_key(&root, "alice", &alice_key);
    write_default_user_ssh_key(&alice_home, &alice_key);

    create_bare_repo(&root, "users", "alice", "public", "dotfiles");
    create_bare_repo(&root, "users", "alice", "private", "vault");
    create_bare_repo(&root, "users", "bob", "public", "widgets");
    create_bare_repo(&root, "users", "bob", "private", "bob-secret");
    create_bare_repo(&root, "teams", "core", "public", "docs");

    let server = start_test_server(&root);
    let addr = server.local_addr().to_string();

    let env = CliEnv {
        addr: None,
        user: Some("alice".to_owned()),
        ssh_key: None,
        home: Some(alice_home),
        cwd: None,
    };

    // 1. List all accessible repositories using default SSH key (~/.ssh/id_ed25519)
    let mut out = Vec::new();
    run_with_env(["--addr", &addr], &env, &mut out).expect("list all repos");
    let text = String::from_utf8(out).expect("utf8 output");
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(
        lines,
        vec![
            "core/docs\tpublic\tteams\tssh://git.example.test/teams/core/public/docs.git",
            "alice/vault\tprivate\tusers\tssh://git.example.test/users/alice/private/vault.git",
            "alice/dotfiles\tpublic\tusers\tssh://git.example.test/users/alice/public/dotfiles.git",
            "bob/widgets\tpublic\tusers\tssh://git.example.test/users/bob/public/widgets.git",
        ]
    );

    // 2. Search across all accessible repositories
    let mut search_out = Vec::new();
    run_with_env(["--addr", &addr, "search", "vault"], &env, &mut search_out)
        .expect("search repos");
    let search_text = String::from_utf8(search_out).expect("utf8 output");
    assert_eq!(
        search_text.lines().collect::<Vec<_>>(),
        vec!["alice/vault\tprivate\tusers\tssh://git.example.test/users/alice/private/vault.git"]
    );

    // 3. Shortcut for listing user's repositories (public and private)
    for shortcut_args in [
        vec!["--addr", addr.as_str(), "user"],
        vec!["--addr", addr.as_str(), "--mine"],
        vec!["--addr", addr.as_str(), "-m"],
    ] {
        let mut user_out = Vec::new();
        run_with_env(shortcut_args, &env, &mut user_out).expect("user repos shortcut");
        let user_text = String::from_utf8(user_out).expect("utf8 output");
        assert_eq!(
            user_text.lines().collect::<Vec<_>>(),
            vec![
                "alice/vault\tprivate\tusers\tssh://git.example.test/users/alice/private/vault.git",
                "alice/dotfiles\tpublic\tusers\tssh://git.example.test/users/alice/public/dotfiles.git",
            ]
        );
    }

    // 4. Unauthenticated mode (--no-auth) only sees public repositories
    let mut anon_out = Vec::new();
    run_with_env(
        ["--addr", &addr, "--no-auth", "user", "alice"],
        &env,
        &mut anon_out,
    )
    .expect("unauthenticated user alice repos");
    let anon_text = String::from_utf8(anon_out).expect("utf8 output");
    assert_eq!(
        anon_text.lines().collect::<Vec<_>>(),
        vec![
            "alice/dotfiles\tpublic\tusers\tssh://git.example.test/users/alice/public/dotfiles.git"
        ]
    );

    server.shutdown();
}

#[test]
fn cli_push_adds_default_or_custom_remote_if_needed_and_pushes_commits() {
    let tmp = TempDir::new("push_e2e");
    let root = tmp.path().join("srv");
    let alice_home = tmp.path().join("home_alice");
    fs::create_dir_all(root.join("users/alice/public")).expect("create public dir");
    fs::create_dir_all(root.join("users/alice/private")).expect("create private dir");

    let alice_key = test_ed25519_key(0x55);
    write_authorized_key(&root, "alice", &alice_key);
    write_default_user_ssh_key(&alice_home, &alice_key);

    // Set up fake-ssh script that delegates to scripts/git-auto-shell with RO_GIT_ROOT
    let git_auto_shell = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .join("scripts/git-auto-shell");
    let fake_ssh = tmp.path().join("fake-ssh");
    fs::write(
        &fake_ssh,
        format!(
            "#!/bin/sh\nset -e\nshift\nRO_GIT_ROOT='{}' exec '{}' -c \"$*\"\n",
            root.display(),
            git_auto_shell.display()
        ),
    )
    .expect("write fake-ssh");
    fs::set_permissions(&fake_ssh, fs::Permissions::from_mode(0o755)).expect("chmod fake-ssh");

    // Initialize local working repository `new-app`
    let work_repo = tmp.path().join("new-app");
    fs::create_dir_all(&work_repo).expect("create work_repo");
    run_git_cmd(&work_repo, &["init", "--initial-branch=main"]);
    run_git_cmd(&work_repo, &["config", "user.name", "Alice"]);
    run_git_cmd(&work_repo, &["config", "user.email", "alice@example.test"]);
    run_git_cmd(
        &work_repo,
        &["config", "core.sshCommand", &fake_ssh.to_string_lossy()],
    );
    fs::write(work_repo.join("README.md"), "# New App\n").expect("write README.md");
    run_git_cmd(&work_repo, &["add", "README.md"]);
    run_git_cmd(&work_repo, &["commit", "-m", "Initial commit"]);

    let server = start_test_server(&root);
    let addr = server.local_addr().to_string();

    let env = CliEnv {
        addr: Some(addr.clone()),
        user: Some("alice".to_owned()),
        ssh_key: None,
        home: Some(alice_home),
        cwd: Some(work_repo.clone()),
    };

    // 1. Default `push` adds `origin` remote via gRPC and pushes to auto-created private repo
    let mut out = Vec::new();
    run_with_env(["push"], &env, &mut out).expect("default push");
    assert!(out.is_empty());

    let origin_url = run_git_cmd(&work_repo, &["remote", "get-url", "--", "origin"]);
    assert_eq!(
        origin_url,
        "ssh://alice@git.example.test/users/alice/private/new-app.git"
    );

    // 2. Subsequent `push` reuses existing `origin` remote without re-adding and pushes new commit
    fs::write(work_repo.join("README.md"), "# New App v2\n").expect("update README.md");
    run_git_cmd(&work_repo, &["add", "README.md"]);
    run_git_cmd(&work_repo, &["commit", "-m", "Second commit"]);
    run_with_env(["push"], &env, &mut out).expect("second push with existing origin");

    // 3. `push` with custom remote (`-r upstream`), explicit visibility (`-v public`), and repo name
    run_with_env(
        ["push", "-r", "upstream", "-v", "public", "public-mirror", "main"],
        &env,
        &mut out,
    )
    .expect("custom remote push");
    let upstream_url = run_git_cmd(&work_repo, &["remote", "get-url", "--", "upstream"]);
    assert_eq!(
        upstream_url,
        "ssh://alice@git.example.test/users/alice/public/public-mirror.git"
    );

    // 4. Verify both pushed repositories are now discoverable via `ro-git-cli user`
    let mut list_out = Vec::new();
    run_with_env(["user"], &env, &mut list_out).expect("list user repos after push");
    let list_text = String::from_utf8(list_out).expect("utf8");
    assert_eq!(
        list_text.lines().collect::<Vec<_>>(),
        vec![
            "alice/new-app\tprivate\tusers\tssh://git.example.test/users/alice/private/new-app.git",
            "alice/public-mirror\tpublic\tusers\tssh://git.example.test/users/alice/public/public-mirror.git",
        ]
    );

    server.shutdown();
}
