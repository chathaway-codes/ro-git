# Read-Only Git (`ro-git`)

A minimalist, database-free SSH Git server and read-only Web UI (`linux/arm64` & `linux/amd64` compatible) for small teams.

`ro-git` combines:
1. **`sshd` + `git-auto-shell`** for Git push/fetch over SSH, with on-the-fly bare repository creation on first push.
2. **Filesystem-enforced authorization** using real Linux users (`/etc/passwd`), POSIX groups (`/etc/group`), and directory mode bits (`chmod`/`chown`/`setgid`)—no SQL/NoSQL database or application-level ACL store.
3. **Stateless SSH Key Authentication (`sshsig`)** allowing users to sign in to the Web UI using their existing SSH key via `ssh-keygen -Y sign`.
4. **Rust (`roto-grpc`) + Yew (WASM) Web UI**:
   - **Milestone 1 (Repository Index)**: Lists discoverable repositories grouped/filterable by user and team with one-click copy-to-clipboard for `git clone` commands and `ssh://` URLs.
   - **Milestone 2 (Repository Browser & Client-Side Markdown Viewer)**: Backend strictly serves raw Git objects over gRPC; the Yew WASM frontend browses repository trees, file blobs, branches/tags, and commit history, and renders `README.md` / `.md` files client-side into Yew virtual DOM nodes (`pulldown-cmark`).

---

## 1. Filesystem Layout & Permission Invariants

All paths are absolute (default root `/`, or configurable prefix `RO_GIT_ROOT` for testing). Short/relative `~` paths are not used:

```text
/users/                                 # root:root         0755 (drwxr-xr-x)
└── <user>/                             # <user>:<user>     0755 (drwxr-xr-x)
    ├── authorized_keys                 # <user>:<user>     0600 (-rw-------) or root:<user> 0640
    ├── public/                         # <user>:<user>     0755 (drwxr-xr-x)
    │   └── <repo>.git/
    └── private/                        # <user>:<user>     0700 (drwx------)
        └── <repo>.git/

/teams/                                 # root:root         0755 (drwxr-xr-x)
└── <team>/                             # root:<team>       0755 (drwxr-xr-x)
    ├── members                         # root:<team>       0640 (-rw-r-----)
    ├── public/                         # root:<team>       2775 (drwxrwsr-x) [setgid!]
    │   └── <repo>.git/
    └── private/                        # root:<team>       2770 (drwxrws---) [setgid!]
        └── <repo>.git/
```

### Key Invariants
- **OpenSSH `StrictModes` compliance**: `/users` must be `root:root 0755`, `/users/<user>` must be owned by `<user>` with mode `0755` (never group- or world-writable), and `/users/<user>/authorized_keys` must be `0600` (owned by `<user>`) or `0640` (owned by `root:<user>`).
- **Private repo isolation**: `/users/<user>/private` is `0700` and `/teams/<team>/private` is `2770` (`root:<team>`). The Linux kernel prevents unauthorized UIDs/GIDs from traversing or listing (`readdir`) those directories.
- **Team `setgid` inheritance**: `/teams/<team>/public` (`2775`) and `/teams/<team>/private` (`2770`) have the `setgid` bit (`g+s`) set so any repository created inside automatically inherits `<team>` group ownership.
- **Declarative User & Group Sync (`git-sync-users`)**: Reconciles `/users/<user>` into `/etc/passwd` (home `/users/<user>`, shell `/usr/local/bin/git-auto-shell`), syncs `/teams/<team>/members` into `/etc/group`, and enforces all directory ownership and mode invariants (`0755`, `0600`/`0640`, `0700`, `2775`, `2770`).

---

## 2. SSH Configuration & On-the-Fly Repo Creation

### `sshd_config` Requirements
```ssh-config
AuthorizedKeysFile /users/%u/authorized_keys
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
StrictModes yes
UsePAM no
```

### Login Shell: `/usr/local/bin/git-auto-shell`
Every Git user in `/etc/passwd` has their home directory set to `/users/<user>` and login shell set to `/usr/local/bin/git-auto-shell`.

When a user pushes to a repository that does not exist yet (`git push ssh://<user>@<host>/users/<user>/private/my-repo.git main`), `sshd` drops privileges to `<user>` (and their supplementary `/etc/group` memberships) before invoking the login shell.

Installed at `/usr/local/bin/git-auto-shell` (`0755 root:root`):

```sh
#!/bin/sh
set -e

# Interactive SSH (no -c): let git-shell reject it
if [ "$1" != "-c" ] || [ -z "$2" ]; then
    exec /usr/bin/git-shell "$@"
fi

cmd="$2"

case "$cmd" in
    git-receive-pack\ *)
        # Extract the path from: git-receive-pack '/path/to/repo.git'
        repo=$(printf '%s\n' "$cmd" | sed -n "s/^git-receive-pack '\(.*\)'$/\1/p")

        # Require exact 4-segment path: /(users|teams)/<owner>/(public|private)/<repo>.git
        if ! printf '%s\n' "$repo" | grep -Eq '^/(users|teams)/[a-zA-Z0-9_-]+/(public|private)/[a-zA-Z0-9_-]+\.git$'; then
            echo "fatal: path must be /(users|teams)/<owner>/(public|private)/<repo>.git" >&2
            exit 1
        fi

        if [ ! -d "$repo" ]; then
            case "$repo" in
                /teams/*)
                    # --shared=group ensures all team members can write objects and refs
                    git init --bare --shared=group --quiet -- "$repo" >&2
                    ;;
                /users/*)
                    git init --bare --quiet -- "$repo" >&2
                    ;;
            esac
        fi
        ;;
esac

exec /usr/bin/git-shell -c "$cmd"
```

*Important*: Any output during initialization MUST go to `stderr` (`>&2`), never `stdout`, so the Git wire protocol stream on `stdout` is not corrupted.

---

## 3. Web Component & Authentication Architecture

### Scope by Milestone
- **Milestone 1 — Repository Index & Clone URLs**:
  1. List discoverable repositories grouped or filterable by owner/team (`/users/<user>/...` and `/teams/<team>/...`).
  2. Provide one-click copy-to-clipboard buttons for each repository's clone command and URL, with an `SSH` / `HTTPS` protocol toggle on public repositories:
     - SSH clone command: `git clone ssh://<host>/users/<owner>/public/<repo>.git` (or `ssh://<user>@<host>/...` when authenticated as `<user>`)
     - Raw SSH URL: `ssh://<host>/users/<owner>/public/<repo>.git`
     - HTTPS clone command (public repos only): `git clone https://<https_host>/users/<owner>/public/<repo>.git`
     - Raw HTTPS URL (public repos only): `https://<https_host>/users/<owner>/public/<repo>.git`
- **Milestone 2 — Read-Only Repository Browser, Smart HTTP Clone & Client-Side Markdown Renderer**:
  1. Backend strictly responds to gRPC requests for repository branches/tags, directory trees, raw file blobs, and commit history.
  2. Read-only Git Smart HTTP (`GET .../info/refs?service=git-upload-pack` and `POST .../git-upload-pack`, supporting Git Wire Protocol v0/v1 and v2) for `/<scope>/<owner>/public/<name>[.git]`, spawning `git-upload-pack` as unprivileged `nobody`. Private repositories and `git-receive-pack` pushes over HTTP are rejected (`403 Forbidden`).
  3. Client-side Markdown engine in Yew WASM (`pulldown-cmark` -> Yew `VNode`) renders `README.md` and `.md` blobs directly in the browser with safe URL filtering and relative repository link routing.

### Visibility, Stateless SSH Auth & Privilege Separation

```mermaid
flowchart LR
    CLI["User CLI (ssh-keygen -Y sign)"] -->|1. Paste SSH Signature| Browser["Browser (Yew WASM)"]
    Browser -->|2. HTTPS + Bearer Token| Server["ro-git Server (roto-grpc + HTTP)"]
    Server -->|3. Spawn Worker as <user>\n(uid, gid, supplementary gids)| Worker["ro-git Worker Subprocess"]
    Worker -->|4. Verify /users/<user>/authorized_keys\n& Read Accessible Repos| Volume["Filesystem (/users, /teams)"]
```

1. **Public / Unauthenticated Requests**:
   - The worker subprocess drops privileges to `nobody` (`65534:65534`, no supplementary groups).
   - At the OS kernel level, `nobody` can only discover and list `/users/*/public/*.git` (`0755`) and `/teams/*/public/*.git` (`2775`), because `/users/*/private` (`0700`) and `/teams/*/private` (`2770`) deny `other`.
2. **Authenticated Requests (Self-Signed SSH Bearer Token)**:
   - **Sign Locally**: The Web UI displays a one-liner for the user (`<user>`) to sign a timestamped payload (`ro-git:v1:<user>:<exp_unix>`):
     ```bash
     printf 'ro-git:v1:charles:1793332200' | ssh-keygen -Y sign -f ~/.ssh/id_ed25519 -n ro-git
     ```
   - **Paste Signature**: The user pastes the `-----BEGIN SSH SIGNATURE-----` block into the Web UI, which encodes `<base64url(payload)>.<base64url(sshsig)>` into `localStorage` and sends `Authorization: Bearer <token>`.
   - **Drop Privileges & Verify**:
     - `ro-git` resolves `<user>`'s `uid`, primary `gid`, and supplementary team `gids` (from `/etc/passwd` + `/etc/group` or filesystem inodes + `/teams/*/members`).
     - `ro-git` spawns `/proc/self/exe git-worker` as `<user>` (`CommandExt::uid(uid).gid(gid).groups(&team_gids)`).
     - Running as `<user>`, the worker has kernel permission to read `/users/<user>/authorized_keys` (`0600`), verifies the `sshsig` signature and expiration (`RO_GIT_MAX_TOKEN_TTL_SECS`), and then lists/reads all public repos plus `/users/<user>/private/*.git` (`0700`) and `/teams/<team>/private/*.git` (`2770`) for the user's teams.

---

## 4. Configuration, Environment Variables & CLI Arguments

### Environment Variables

| Variable | Default | Component | Description |
| :--- | :--- | :--- | :--- |
| `RO_GIT_LISTEN_ADDR` | `0.0.0.0:8080` | `ro-git-server` | TCP socket address for the unified `roto-grpc` (gRPC + HTTP/1.1 + HTTP/2) server. |
| `RO_GIT_ROOT` | `/` | `ro-git-server`, `git-auto-shell`, `git-sync-users` | Root prefix containing `users/` and `teams/` directories (e.g., `/` in container, or a temp dir in tests). |
| `RO_GIT_SSH_HOST` | `localhost` | `ro-git-server` | Public SSH hostname (and optional `:port`, e.g., `git.example.com:2222`) used when formatting `ssh://` and `git clone` URLs in the UI. |
| `RO_GIT_HTTPS_HOST` / `RO_GIT_PUBLIC_URL` | `localhost` | `ro-git-server` | Public HTTPS hostname or base URL (e.g., `git.example.com` or `https://git.example.com`) used when formatting HTTPS clone URLs for public repositories (terminated by an external HTTPS reverse proxy). |
| `RO_GIT_STATIC_DIR` | `/app/dist` | `ro-git-server` | Path to compiled Yew WASM frontend assets (`index.html`, `.wasm`, `.js`). |
| `RO_GIT_MAX_TOKEN_TTL_SECS` | `2592000` | `ro-git-server` | Maximum allowed SSH bearer token lifetime in seconds (default: 30 days). |
| `RO_GIT_NOBODY_UID` | `65534` | `ro-git-server` | Unprivileged UID/GID used by the worker subprocess for anonymous requests. |
| `RO_GIT_DEV_USER` | *(unset)* | `ro-git-server` | Optional fallback username for local development when no `Authorization` header is present. |
| `RO_GIT_ETC_DIR` | `<RO_GIT_ROOT>/etc` (or `/etc`) | `ro-git-server`, `git-sync-users` | Directory containing `passwd` and `group` files used for UID/GID and team membership resolution. |
| `RO_GIT_WORKER_BIN` | *(auto-detected)* | `ro-git-server` | Optional explicit path to the `ro-git-server` binary invoked when spawning `git-worker` subprocesses. |
| `GIT_SYNC_USERS_BIN` | `/usr/local/bin/git-sync-users` | `docker-entrypoint.sh` | Path to the `git-sync-users` executable run at container startup. |
| `SSH_KEYGEN_BIN` | `/usr/bin/ssh-keygen` | `docker-entrypoint.sh` | Path to `ssh-keygen` used to generate missing SSH host keys (`-A`) at startup. |
| `SSHD_BIN` | `/usr/sbin/sshd` | `docker-entrypoint.sh` | Path to the OpenSSH daemon executable launched at startup. |
| `RO_GIT_SERVER_BIN` | `/usr/local/bin/ro-git-server` | `docker-entrypoint.sh` | Path to the `ro-git-server` binary `exec`'d as PID 1 when no custom command is passed. |
| `GIT_SHELL_BIN` | `/usr/bin/git-shell` | `git-auto-shell` | Path to the underlying `git-shell` binary delegated to by `git-auto-shell`. |

### Command-Line Arguments & Entrypoint Behavior

- **`/usr/local/bin/docker-entrypoint.sh [command [args...]]`** (Container `ENTRYPOINT`):
  1. Executes `git-sync-users` (`>&2`) to reconcile `/users` and `/teams` into `/etc/passwd` and `/etc/group` and enforce filesystem ownership and permission invariants.
  2. Executes `ssh-keygen -A` (`>&2`) to generate any missing OpenSSH host keys under `/etc/ssh`.
  3. **Default (no arguments)**: Starts `/usr/sbin/sshd -e` (`>&2`) in the background and `exec`s `/usr/local/bin/ro-git-server` in the foreground.
  4. **Custom command (`command [args...]`)**: After running reconciliation and host-key generation, replaces the process with `exec "$@"` (useful for one-off maintenance or inspection).
- **`/usr/local/bin/ro-git-server [--ssh-host <HOST>] [--https-host <HOST> | --public-url <URL>] [git-worker]`**:
  - **Server mode**: Starts the HTTP/1.1 + HTTP/2 + `roto-grpc` server configured via `RO_GIT_*` environment variables and optional `--ssh-host` / `--https-host` / `--public-url` CLI flags.
  - **`git-worker`**: Runs as a privilege-separated single-request worker subprocess (reads one length-prefixed Protobuf `WorkerRequest` from `stdin` and writes one length-prefixed `WorkerResponse` to `stdout`).
- **`/usr/local/bin/git-sync-users [--root <PATH>] [--etc-dir <PATH>]`**:
  - `--root <PATH>`: Root directory containing `users/` and `teams/` (overrides `RO_GIT_ROOT`, defaults to `/`).
  - `--etc-dir <PATH>`: Directory containing `passwd` and `group` (overrides `RO_GIT_ETC_DIR`, defaults to `<root>/etc`).

### Configuration Files

- **`/etc/ssh/sshd_config`** (baked into the image from `config/sshd_config`, mode `0644`):
  Enforces SSH public-key authentication from `/users/%u/authorized_keys`, disables passwords/PAM/root login, and requires `StrictModes yes`.

---

## 5. Running the Production Docker Image & Persistent Volumes

### Building the Production Image

The multi-stage `Dockerfile` includes a minimal `production` target (`debian:bookworm-slim` with `openssh-server`, `git`, `python3`, `git-auto-shell`, `git-sync-users`, `ro-git-server`, and compiled Yew WASM static assets in `/app/dist`):

```bash
# Build production image (ro-git:latest)
make docker-prod
# Or directly with Docker:
docker build --target production -t ro-git:latest .
```

### Expected Persistent Volumes / Disks

Because `ro-git` is completely database-free, all state lives directly on the filesystem. Mount POSIX-compliant persistent volumes or host disks (supporting `chown`, `chmod`, and `setgid` bits) at the following container paths:

| Container Mount Path | Requirement | Purpose & Contents |
| :--- | :--- | :--- |
| `/users` | **Required** | Stores per-user directories (`/users/<user>`), SSH public keys (`/users/<user>/authorized_keys`), and bare user Git repositories (`/users/<user>/public/<repo>.git` and `/users/<user>/private/<repo>.git`). Must support POSIX ownership and `0755` / `0700` / `0600` modes for OpenSSH `StrictModes`. |
| `/teams` | **Required** *(if using teams)* | Stores per-team directories (`/teams/<team>`), team membership lists (`/teams/<team>/members`), and shared bare team Git repositories (`/teams/<team>/public/<repo>.git` and `/teams/<team>/private/<repo>.git`). Must support POSIX group ownership and `setgid` modes (`2775` / `2770`). |
| `/etc/ssh` | **Recommended** | Persists OpenSSH server host keys (`/etc/ssh/ssh_host_*_key*` generated by `ssh-keygen -A`) across container recreations so Git SSH clients do not fail with `REMOTE HOST IDENTIFICATION HAS CHANGED`. *(Note: When using a named Docker volume on `/etc/ssh`, Docker automatically initializes it with the image's `/etc/ssh/sshd_config`; if bind-mounting an empty host directory over `/etc/ssh`, copy `config/sshd_config` to `/etc/ssh/sshd_config` first or bind-mount only the `ssh_host_*` key files.)* |

### Running the Container

```bash
# 1. Create named persistent volumes for user repos, team repos, and SSH host keys
docker volume create ro-git-users
docker volume create ro-git-teams
docker volume create ro-git-ssh

# 2. Run the production container (publishing SSH on 2222 and Web UI / gRPC on 8080)
docker run -d \
  --name ro-git \
  --restart unless-stopped \
  -p 2222:22 \
  -p 8080:8080 \
  -e RO_GIT_LISTEN_ADDR=0.0.0.0:8080 \
  -e RO_GIT_SSH_HOST=localhost:2222 \
  -e RO_GIT_MAX_TOKEN_TTL_SECS=2592000 \
  -v ro-git-users:/users \
  -v ro-git-teams:/teams \
  -v ro-git-ssh:/etc/ssh \
  ro-git:latest
```

### Provisioning Users & Teams on Persistent Volumes

Whenever you add or modify `/users/<user>/authorized_keys` or `/teams/<team>/members` on a running container, run `git-sync-users` (or restart the container) to reconcile `/etc/passwd`, `/etc/group`, and directory permissions:

```bash
# Provision a user ("alice") and a team ("core") inside the persistent volumes
docker exec ro-git sh -c '
  mkdir -p /users/alice /teams/core &&
  printf "%s\n" "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... alice@example.com" > /users/alice/authorized_keys &&
  printf "%s\n" "alice" > /teams/core/members &&
  /usr/local/bin/git-sync-users
'

# Push a new repository (created on the fly by git-auto-shell on first push)
git push ssh://alice@localhost:2222/users/alice/public/hello.git main
git push ssh://alice@localhost:2222/teams/core/private/secret.git main
```

---

## 6. Development & Workspace Commands

All development dependencies—including the Rust stable toolchain, `wasm32-unknown-unknown` target, `protoc`, `cargo-roto`, `protoc-gen-roto`, `protoc-gen-roto-grpc`, `trunk`, `wasm-bindgen`, and `binaryen`—are pre-installed in the development `Dockerfile`.

### 1. Build & Enter the Development Container
```bash
# Build the development Docker image (ro-git-workspace:latest)
make docker-build

# Build the production Docker image (ro-git:latest)
make docker-prod

# Launch an interactive shell inside the container
make docker-shell

# Run the test suite inside the container
make docker-test

# Spawn isolated Antigravity daemon in YOLO mode
make docker-yolo
```

### 2. Run Verification & Issue Tracker
```bash
# Run full verification suite
make test

# List open issues ready for pickup
make issues-ready

# Create a new issue
./scripts/issue create milestone_0 "Implement feature X"

# Launch read-only issue viewer Web UI on port 8080
make issues-ui
```
