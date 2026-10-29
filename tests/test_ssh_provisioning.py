#!/usr/bin/env python3
"""
tests/test_ssh_provisioning.py - Unit and integration tests for sshd_config,
git-auto-shell, and git-sync-users.
"""

import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest

REPO_ROOT = Path(__file__).resolve().parent.parent
SSHD_CONFIG_PATH = REPO_ROOT / "config" / "sshd_config"
GIT_AUTO_SHELL_PATH = REPO_ROOT / "scripts" / "git-auto-shell"
GIT_SYNC_USERS_PATH = REPO_ROOT / "scripts" / "git-sync-users"


class TestSshdConfig(unittest.TestCase):
    def test_sshd_config_directives(self):
        self.assertTrue(SSHD_CONFIG_PATH.exists(), "config/sshd_config must exist")
        directives = {}
        for raw_line in SSHD_CONFIG_PATH.read_text(encoding="utf-8").splitlines():
            line = raw_line.split("#", 1)[0].strip()
            if not line:
                continue
            parts = line.split(None, 1)
            self.assertEqual(len(parts), 2, f"Malformed sshd_config line: {raw_line!r}")
            directives[parts[0]] = parts[1]

        expected = {
            "AuthorizedKeysFile": "/users/%u/authorized_keys",
            "PasswordAuthentication": "no",
            "KbdInteractiveAuthentication": "no",
            "PermitRootLogin": "no",
            "StrictModes": "yes",
            "UsePAM": "no",
        }
        for key, val in expected.items():
            self.assertEqual(directives.get(key), val, f"Mismatch for {key}")


class TestGitAutoShell(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        (self.root / "users" / "alice" / "public").mkdir(parents=True)
        (self.root / "users" / "alice" / "private").mkdir(parents=True)
        (self.root / "teams" / "core" / "public").mkdir(parents=True)
        (self.root / "teams" / "core" / "private").mkdir(parents=True)

        # Create a mock git-shell that records arguments to stderr and outputs nothing to stdout
        self.mock_git_shell = self.root / "mock-git-shell"
        self.mock_git_shell.write_text(
            "#!/bin/sh\n"
            "if [ \"$1\" != \"-c\" ] || [ -z \"$2\" ]; then\n"
            "    echo \"fatal: Interactive git shell is not enabled.\" >&2\n"
            "    exit 128\n"
            "fi\n"
            "printf 'EXEC:%s\\n' \"$2\" >&2\n"
            "exit 0\n",
            encoding="utf-8",
        )
        self.mock_git_shell.chmod(0o755)

    def tearDown(self):
        self.temp_dir.cleanup()

    def _run_shell(self, args, use_mock_shell=True):
        env = os.environ.copy()
        env["RO_GIT_ROOT"] = str(self.root)
        if use_mock_shell:
            env["GIT_SHELL_BIN"] = str(self.mock_git_shell)
        return subprocess.run(
            [str(GIT_AUTO_SHELL_PATH), *args],
            env=env,
            capture_output=True,
            text=True,
        )

    def test_executable_mode(self):
        self.assertTrue(os.access(GIT_AUTO_SHELL_PATH, os.X_OK))

    def test_rejects_interactive_login(self):
        res_no_args = self._run_shell([], use_mock_shell=False)
        self.assertNotEqual(res_no_args.returncode, 0)
        self.assertEqual(res_no_args.stdout, "")

        res_empty_cmd = self._run_shell(["-c", ""], use_mock_shell=False)
        self.assertNotEqual(res_empty_cmd.returncode, 0)
        self.assertEqual(res_empty_cmd.stdout, "")

        res_bad_cmd = self._run_shell(["-c", "id"], use_mock_shell=False)
        self.assertNotEqual(res_bad_cmd.returncode, 0)
        self.assertEqual(res_bad_cmd.stdout, "")

    def test_rejects_invalid_paths(self):
        invalid_paths = [
            "/users/alice/../../etc/passwd.git",
            "/users/alice/public/../private/repo.git",
            "/users/alice/public/repo",
            "/users/alice/repo.git",
            "/users/alice/public/nested/repo.git",
            "/users/alice/internal/repo.git",
            "/orgs/alice/public/repo.git",
            "users/alice/public/repo.git",
            "/users/alice/public/.git",
            "/users/alice/public/repo.git\n/users/alice/public/other.git",
        ]
        for bad_path in invalid_paths:
            with self.subTest(path=bad_path):
                res = self._run_shell(["-c", f"git-receive-pack '{bad_path}'"])
                self.assertNotEqual(res.returncode, 0)
                self.assertEqual(res.stdout, "")
                self.assertIn(
                    "fatal: path must be /(users|teams)/<owner>/(public|private)/<repo>.git",
                    res.stderr,
                )

    def test_auto_init_user_public_and_private_repos_with_zero_stdout(self):
        for vis in ("public", "private"):
            logical_path = f"/users/alice/{vis}/app-{vis}.git"
            fs_path = self.root / "users" / "alice" / vis / f"app-{vis}.git"
            self.assertFalse(fs_path.exists())

            res = self._run_shell(["-c", f"git-receive-pack '{logical_path}'"])
            self.assertEqual(res.returncode, 0, res.stderr)
            # Zero bytes may leak to stdout during initialization
            self.assertEqual(res.stdout, "")
            self.assertTrue((fs_path / "HEAD").exists())
            self.assertIn(f"EXEC:git-receive-pack '{fs_path}'", res.stderr)

            # Verify core.bare is true and sharedRepository is not forced on user repos
            bare_cfg = subprocess.run(
                ["git", "--git-dir", str(fs_path), "config", "--get", "core.bare"],
                capture_output=True,
                text=True,
                check=True,
            )
            self.assertEqual(bare_cfg.stdout.strip(), "true")

    def test_auto_init_team_public_and_private_repos_with_shared_group(self):
        for vis in ("public", "private"):
            logical_path = f"/teams/core/{vis}/service-{vis}.git"
            fs_path = self.root / "teams" / "core" / vis / f"service-{vis}.git"
            self.assertFalse(fs_path.exists())

            res = self._run_shell(["-c", f"git-receive-pack '{logical_path}'"])
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertEqual(res.stdout, "")
            self.assertTrue((fs_path / "HEAD").exists())

            shared_cfg = subprocess.run(
                ["git", "--git-dir", str(fs_path), "config", "--get", "core.sharedrepository"],
                capture_output=True,
                text=True,
                check=True,
            )
            self.assertIn(shared_cfg.stdout.strip(), ("1", "group", "true"))

    def test_upload_pack_does_not_auto_create_missing_repo(self):
        logical_path = "/users/alice/public/nonexistent.git"
        fs_path = self.root / "users" / "alice" / "public" / "nonexistent.git"
        res = self._run_shell(["-c", f"git-upload-pack '{logical_path}'"])
        self.assertEqual(res.returncode, 0)
        self.assertEqual(res.stdout, "")
        self.assertFalse(fs_path.exists())

    def test_accepts_ro_git_root_prefixed_path(self):
        fs_path = self.root / "users" / "alice" / "public" / "prefixed.git"
        res = self._run_shell(["-c", f"git-receive-pack '{fs_path}'"])
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual(res.stdout, "")
        self.assertTrue((fs_path / "HEAD").exists())

    def test_end_to_end_git_push_and_clone_over_git_auto_shell(self):
        # Create a fake ssh wrapper that invokes git-auto-shell with real /usr/bin/git-shell
        ssh_wrapper = self.root / "fake-ssh"
        ssh_wrapper.write_text(
            "#!/bin/sh\n"
            "# Discard ssh host argument ($1) and forward remaining args (-c ... or command)\n"
            "shift\n"
            f"exec '{GIT_AUTO_SHELL_PATH}' -c \"$*\"\n",
            encoding="utf-8",
        )
        ssh_wrapper.chmod(0o755)

        work_repo = self.root / "work"
        work_repo.mkdir()
        subprocess.run(["git", "init", "-b", "main"], cwd=work_repo, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.name", "Alice"], cwd=work_repo, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.email", "alice@example.com"], cwd=work_repo, check=True, capture_output=True)
        (work_repo / "README.md").write_text("# Hello ro-git\n", encoding="utf-8")
        subprocess.run(["git", "add", "README.md"], cwd=work_repo, check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "Initial commit"], cwd=work_repo, check=True, capture_output=True)

        env = os.environ.copy()
        env["RO_GIT_ROOT"] = str(self.root)
        env["GIT_SSH_COMMAND"] = str(ssh_wrapper)

        remote_url = "ssh://alice@localhost/users/alice/private/first-push.git"
        push_res = subprocess.run(
            ["git", "push", remote_url, "main"],
            cwd=work_repo,
            env=env,
            capture_output=True,
            text=True,
        )
        self.assertEqual(push_res.returncode, 0, push_res.stderr)

        clone_dir = self.root / "cloned"
        clone_res = subprocess.run(
            ["git", "clone", remote_url, str(clone_dir)],
            env=env,
            capture_output=True,
            text=True,
        )
        self.assertEqual(clone_res.returncode, 0, clone_res.stderr)
        self.assertEqual((clone_dir / "README.md").read_text(encoding="utf-8"), "# Hello ro-git\n")


class TestGitSyncUsers(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.etc = self.root / "etc"

    def tearDown(self):
        self.temp_dir.cleanup()

    def _run_sync(self):
        env = os.environ.copy()
        env["RO_GIT_ROOT"] = str(self.root)
        env["RO_GIT_ETC_DIR"] = str(self.etc)
        return subprocess.run(
            [str(GIT_SYNC_USERS_PATH)],
            env=env,
            capture_output=True,
            text=True,
        )

    def test_reconciles_users_teams_and_is_idempotent(self):
        # Set up users with intentionally overly-permissive initial modes
        alice_dir = self.root / "users" / "alice"
        bob_dir = self.root / "users" / "bob"
        alice_dir.mkdir(parents=True)
        bob_dir.mkdir(parents=True)
        os.chmod(alice_dir, 0o777)

        auth_keys = alice_dir / "authorized_keys"
        auth_keys.write_text("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest alice@host\n", encoding="utf-8")
        os.chmod(auth_keys, 0o666)

        # Set up team with comments and blank lines in members
        team_dir = self.root / "teams" / "backend"
        team_dir.mkdir(parents=True)
        os.chmod(team_dir, 0o777)
        members_file = team_dir / "members"
        members_file.write_text(
            "# Backend team members\n"
            "\n"
            "alice\n"
            "bob # inline comment\n"
            "alice\n",
            encoding="utf-8",
        )
        os.chmod(members_file, 0o666)

        res1 = self._run_sync()
        self.assertEqual(res1.returncode, 0, res1.stderr)
        # Rule of Silence: no stdout chatter on success
        self.assertEqual(res1.stdout, "")

        passwd_1 = (self.etc / "passwd").read_text(encoding="utf-8")
        group_1 = (self.etc / "group").read_text(encoding="utf-8")

        self.assertIn("alice:x:1000:1000:alice:/users/alice:/usr/local/bin/git-auto-shell\n", passwd_1)
        self.assertIn("bob:x:1001:1001:bob:/users/bob:/usr/local/bin/git-auto-shell\n", passwd_1)
        self.assertIn("alice:x:1000:\n", group_1)
        self.assertIn("bob:x:1001:\n", group_1)
        self.assertIn("backend:x:2000:alice,bob\n", group_1)

        # Verify StrictModes and setgid permission invariants
        self.assertEqual(stat.S_IMODE((self.root / "users").stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE(alice_dir.stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE(auth_keys.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE((alice_dir / "public").stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE((alice_dir / "private").stat().st_mode), 0o700)

        self.assertEqual(stat.S_IMODE((self.root / "teams").stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE(team_dir.stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE(members_file.stat().st_mode), 0o640)
        self.assertEqual(stat.S_IMODE((team_dir / "public").stat().st_mode), 0o2775)
        self.assertEqual(stat.S_IMODE((team_dir / "private").stat().st_mode), 0o2770)

        # Re-run to verify idempotency
        res2 = self._run_sync()
        self.assertEqual(res2.returncode, 0, res2.stderr)
        self.assertEqual((self.etc / "passwd").read_text(encoding="utf-8"), passwd_1)
        self.assertEqual((self.etc / "group").read_text(encoding="utf-8"), group_1)

    def test_prunes_removed_users_and_preserves_system_accounts(self):
        self.etc.mkdir(parents=True)
        (self.etc / "passwd").write_text(
            "root:x:0:0:root:/root:/bin/sh\n"
            "sshd:x:74:74:Privilege-separated SSH:/var/empty/sshd:/sbin/nologin\n"
            "developer:x:1000:1000:Developer:/home/developer:/bin/bash\n"
            "nobody:x:65534:65534:nobody:/:/usr/sbin/nologin\n",
            encoding="utf-8",
        )
        (self.etc / "group").write_text(
            "root:x:0:\n"
            "sshd:x:74:\n"
            "developer:x:1000:\n"
            "nobody:x:65534:\n",
            encoding="utf-8",
        )

        (self.root / "users" / "alice").mkdir(parents=True)
        (self.root / "users" / "charlie").mkdir(parents=True)
        self.assertEqual(self._run_sync().returncode, 0)

        passwd_before = (self.etc / "passwd").read_text(encoding="utf-8")
        self.assertIn("developer:x:1000:1000:Developer:/home/developer:/bin/bash\n", passwd_before)
        self.assertIn("alice:x:1001:1001:alice:/users/alice:/usr/local/bin/git-auto-shell\n", passwd_before)
        self.assertIn("charlie:x:1002:1002:charlie:/users/charlie:/usr/local/bin/git-auto-shell\n", passwd_before)

        # Remove charlie directory and re-sync
        for sub in ("public", "private"):
            (self.root / "users" / "charlie" / sub).rmdir()
        (self.root / "users" / "charlie").rmdir()

        self.assertEqual(self._run_sync().returncode, 0)
        passwd_after = (self.etc / "passwd").read_text(encoding="utf-8")
        self.assertIn("developer:x:1000:1000:Developer:/home/developer:/bin/bash\n", passwd_after)
        self.assertIn("alice:x:1001:1001:alice:/users/alice:/usr/local/bin/git-auto-shell\n", passwd_after)
        self.assertNotIn("charlie:", passwd_after)

    def test_rejects_symlinks_in_user_and_team_trees(self):
        target_file = self.root / "secret_target"
        target_file.write_text("sensitive\n", encoding="utf-8")
        os.chmod(target_file, 0o644)

        alice_dir = self.root / "users" / "alice"
        alice_dir.mkdir(parents=True)
        (alice_dir / "authorized_keys").symlink_to(target_file)

        res = self._run_sync()
        self.assertNotEqual(res.returncode, 0)
        # Ensure target file mode was NOT modified via symlink
        self.assertEqual(stat.S_IMODE(target_file.stat().st_mode), 0o644)

        # Also verify symlinked public directory is rejected
        (alice_dir / "authorized_keys").unlink()
        target_dir = self.root / "target_dir"
        target_dir.mkdir()
        os.chmod(target_dir, 0o700)
        (alice_dir / "public").symlink_to(target_dir)

        res_dir = self._run_sync()
        self.assertNotEqual(res_dir.returncode, 0)
        self.assertEqual(stat.S_IMODE(target_dir.stat().st_mode), 0o700)

    def test_shared_user_and_team_name_has_consistent_gid(self):
        (self.root / "users" / "devops").mkdir(parents=True)
        (self.root / "users" / "alice").mkdir(parents=True)
        team_dir = self.root / "teams" / "devops"
        team_dir.mkdir(parents=True)
        (team_dir / "members").write_text("devops\nalice\n", encoding="utf-8")

        res1 = self._run_sync()
        self.assertEqual(res1.returncode, 0, res1.stderr)

        passwd_text = (self.etc / "passwd").read_text(encoding="utf-8")
        group_text = (self.etc / "group").read_text(encoding="utf-8")

        # Extract devops primary GID from passwd and group GID from group
        passwd_gids = {
            line.split(":")[0]: int(line.split(":")[3])
            for line in passwd_text.splitlines()
            if line.strip()
        }
        group_gids = {
            line.split(":")[0]: int(line.split(":")[2])
            for line in group_text.splitlines()
            if line.strip()
        }
        self.assertEqual(passwd_gids["devops"], group_gids["devops"])
        self.assertIn(f"devops:x:{group_gids['devops']}:devops,alice\n", group_text)

        # Verify idempotency on second run
        res2 = self._run_sync()
        self.assertEqual(res2.returncode, 0, res2.stderr)
        self.assertEqual((self.etc / "passwd").read_text(encoding="utf-8"), passwd_text)
        self.assertEqual((self.etc / "group").read_text(encoding="utf-8"), group_text)


class TestProductionDockerAndEntrypoint(unittest.TestCase):
    def test_dockerfile_multi_stage_and_production_invariants(self):
        dockerfile = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn("FROM debian:bookworm-slim AS toolchain", dockerfile)
        self.assertIn("FROM toolchain AS workspace", dockerfile)
        self.assertIn("FROM toolchain AS builder", dockerfile)
        self.assertIn("FROM debian:bookworm-slim AS production", dockerfile)
        self.assertIn("aarch64|arm64", dockerfile)
        self.assertIn("x86_64|amd64", dockerfile)
        self.assertIn("BINARYEN_VERSION", dockerfile)
        self.assertIn("bin/wasm-opt", dockerfile)
        self.assertIn("cargo build --release --locked -p ro-git-server", dockerfile)
        self.assertIn("trunk build --release --config crates/ro-git-ui/Trunk.toml --dist /build/dist", dockerfile)
        self.assertIn("/usr/local/bin/ro-git-server", dockerfile)
        self.assertIn("/usr/local/bin/git-auto-shell", dockerfile)
        self.assertIn("/usr/local/bin/git-sync-users", dockerfile)
        self.assertIn("/usr/local/bin/docker-entrypoint.sh", dockerfile)
        self.assertIn("/usr/local/share/ro-git/sshd_config", dockerfile)
        self.assertIn("/etc/ssh/sshd_config", dockerfile)
        self.assertIn("EXPOSE 22 8080", dockerfile)
        self.assertIn('ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]', dockerfile)

        entrypoint_text = (REPO_ROOT / "scripts" / "docker-entrypoint.sh").read_text(encoding="utf-8")
        self.assertIn('SSHD_BIN="${SSHD_BIN:-/usr/sbin/sshd}"', entrypoint_text)
        self.assertIn(
            'SSHD_CONFIG_DEFAULT_PATH="${SSHD_CONFIG_DEFAULT_PATH:-/usr/local/share/ro-git/sshd_config}"',
            entrypoint_text,
        )

    def test_docker_entrypoint_default_and_custom_command(self):
        entrypoint = REPO_ROOT / "scripts" / "docker-entrypoint.sh"
        self.assertTrue(os.access(entrypoint, os.X_OK))

        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            log_file = tmp_dir / "calls.log"
            seeded_sshd_config = tmp_dir / "etc" / "ssh" / "sshd_config"

            def make_stub(name: str) -> Path:
                p = tmp_dir / name
                p.write_text(
                    "#!/bin/sh\n"
                    f"printf '%s:%s\\n' '{name}' \"$*\" >> '{log_file}'\n"
                    "printf 'diag-%s\\n' '" + name + "'\n",
                    encoding="utf-8",
                )
                p.chmod(0o755)
                return p

            sync_stub = make_stub("git-sync-users")
            keygen_stub = make_stub("ssh-keygen")
            sshd_stub = make_stub("sshd")
            server_stub = tmp_dir / "ro-git-server"
            server_stub.write_text(
                "#!/bin/sh\n"
                f"printf 'ro-git-server:%s\\n' \"$*\" >> '{log_file}'\n",
                encoding="utf-8",
            )
            server_stub.chmod(0o755)

            env = os.environ.copy()
            env["GIT_SYNC_USERS_BIN"] = str(sync_stub)
            env["SSH_KEYGEN_BIN"] = str(keygen_stub)
            env["SSHD_BIN"] = str(sshd_stub)
            env["RO_GIT_SERVER_BIN"] = str(server_stub)
            env["SSHD_CONFIG_PATH"] = str(seeded_sshd_config)
            env["SSHD_CONFIG_DEFAULT_PATH"] = str(SSHD_CONFIG_PATH)

            self.assertFalse(seeded_sshd_config.exists())
            res = subprocess.run([str(entrypoint)], env=env, capture_output=True, text=True)
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertEqual(res.stdout, "")
            self.assertTrue(seeded_sshd_config.is_file(), "sshd_config must be auto-seeded when missing")
            self.assertEqual(stat.S_IMODE(seeded_sshd_config.stat().st_mode), 0o644)
            self.assertEqual(
                seeded_sshd_config.read_text(encoding="utf-8"),
                SSHD_CONFIG_PATH.read_text(encoding="utf-8"),
            )
            self.assertEqual(
                log_file.read_text(encoding="utf-8").splitlines(),
                [
                    "git-sync-users:",
                    "ssh-keygen:-A",
                    "sshd:-e",
                    "ro-git-server:",
                ],
            )

            # Verify existing sshd_config is preserved and custom command passthrough works
            custom_cfg = "# custom sshd_config\nPort 2222\n"
            seeded_sshd_config.write_text(custom_cfg, encoding="utf-8")
            log_file.unlink()
            res_cmd = subprocess.run(
                [str(entrypoint), "printf", "%s", "custom-ok"],
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(res_cmd.returncode, 0, res_cmd.stderr)
            self.assertEqual(res_cmd.stdout, "custom-ok")
            self.assertEqual(seeded_sshd_config.read_text(encoding="utf-8"), custom_cfg)
            self.assertEqual(
                log_file.read_text(encoding="utf-8").splitlines(),
                [
                    "git-sync-users:",
                    "ssh-keygen:-A",
                ],
            )


if __name__ == "__main__":
    unittest.main()
