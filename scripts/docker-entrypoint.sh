#!/bin/sh
set -e

GIT_SYNC_USERS_BIN="${GIT_SYNC_USERS_BIN:-/usr/local/bin/git-sync-users}"
SSH_KEYGEN_BIN="${SSH_KEYGEN_BIN:-/usr/bin/ssh-keygen}"
SSHD_BIN="${SSHD_BIN:-/usr/sbin/sshd}"
RO_GIT_SERVER_BIN="${RO_GIT_SERVER_BIN:-/usr/local/bin/ro-git-server}"
SSHD_CONFIG_PATH="${SSHD_CONFIG_PATH:-/etc/ssh/sshd_config}"
SSHD_CONFIG_DEFAULT_PATH="${SSHD_CONFIG_DEFAULT_PATH:-/usr/local/share/ro-git/sshd_config}"

# Reconcile /users and /teams into /etc/passwd and /etc/group and enforce modes
"$GIT_SYNC_USERS_BIN" >&2

# Auto-seed /etc/ssh/sshd_config if missing (e.g. empty volume mount over /etc/ssh)
if [ ! -f "$SSHD_CONFIG_PATH" ] && [ -f "$SSHD_CONFIG_DEFAULT_PATH" ]; then
    mkdir -p -- "$(dirname -- "$SSHD_CONFIG_PATH")" >&2
    cp -- "$SSHD_CONFIG_DEFAULT_PATH" "$SSHD_CONFIG_PATH" >&2
    chmod 0644 -- "$SSHD_CONFIG_PATH" >&2
fi

# Ensure OpenSSH host keys exist
"$SSH_KEYGEN_BIN" -A >&2

if [ "$#" -eq 0 ]; then
    "$SSHD_BIN" -e >&2
    exec "$RO_GIT_SERVER_BIN"
fi

exec "$@"
