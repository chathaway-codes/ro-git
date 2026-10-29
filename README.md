# Read-Only Git (`ro-git`)

A minimalist, database-free SSH Git server and read-only Web UI (`linux/arm64` & `linux/amd64` compatible) for small teams.

`ro-git` combines:
1. **`sshd` + `git-auto-shell`** for Git push/fetch over SSH, with on-the-fly bare repository creation on first push.
2. **Filesystem-enforced authorization** using real Linux users (`/etc/passwd`), POSIX groups (`/etc/group`), and directory mode bits (`chmod`/`chown`/`setgid`)—no SQL/NoSQL database or application-level ACL store.
3. **Stateless SSH Key Authentication (`sshsig`)** allowing users to sign in to the Web UI using their existing SSH key via `ssh-keygen -Y sign`.
4. **Rust (`roto-grpc`) + Yew (WASM) Web UI**:
   - **Milestone 1 (Repository Index)**: Lists discoverable repositories grouped/filterable by user and team with one-click copy-to-clipboard for `git clone` commands and `ssh://` URLs.
   - **Milestone 2 (Repository Browser & Markdown Viewer)**: Browse repository trees, file blobs, branches/tags, commit history, and render `README.md` / `.md` files into sanitized HTML.

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
  2. Provide one-click copy-to-clipboard buttons for each repository's clone command and raw SSH URL:
     - Clone command: `git clone ssh://<host>/users/<owner>/public/<repo>.git` (or `ssh://<user>@<host>/...` when authenticated as `<user>`)
     - Raw SSH URL: `ssh://<host>/users/<owner>/public/<repo>.git`
- **Milestone 2 — Read-Only Repository Browser & Markdown Renderer**:
  1. Inspect repository branches/tags, directory trees, file blobs, and commit history.
  2. Render `README.md` and `.md` blobs into sanitized HTML.

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

## 4. Configuration (Environment Variables)

| Variable | Default | Description |
| :--- | :--- | :--- |
| `RO_GIT_LISTEN_ADDR` | `0.0.0.0:8080` | TCP address for the unified `roto-grpc` (gRPC + HTTP/1.1 + HTTP/2) server. |
| `RO_GIT_ROOT` | `/` | Root prefix containing `users/` and `teams/` directories (e.g., `/` in container, or a temp dir in tests). |
| `RO_GIT_SSH_HOST` | `localhost` | Public SSH hostname (and optional `:port`) used when formatting `ssh://` and `git clone` URLs in the UI. |
| `RO_GIT_STATIC_DIR` | `/app/dist` | Path to compiled Yew WASM frontend assets (`index.html`, `.wasm`, `.js`). |
| `RO_GIT_MAX_TOKEN_TTL_SECS` | `2592000` | Maximum allowed token lifetime in seconds (default: 30 days). |
| `RO_GIT_NOBODY_UID` | `65534` | Unprivileged UID/GID used by the worker subprocess for anonymous requests. |
| `RO_GIT_DEV_USER` | *(unset)* | Optional fallback username for local development when no `Authorization` header is present. |

---

## Development & Workspace Commands

All development dependencies—including the Rust stable toolchain, `wasm32-unknown-unknown` target, `protoc`, `cargo-roto`, `protoc-gen-roto`, `protoc-gen-roto-grpc`, `trunk`, `wasm-bindgen`, and `binaryen`—are pre-installed in the development `Dockerfile`.

### 1. Build & Enter the Development Container
```bash
# Build the development Docker image (ro-git-workspace:latest)
make docker-build

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
