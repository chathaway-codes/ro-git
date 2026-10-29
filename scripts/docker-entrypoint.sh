#!/bin/sh
set -e

GIT_SYNC_USERS_BIN="${GIT_SYNC_USERS_BIN:-/usr/local/bin/git-sync-users}"
SSH_KEYGEN_BIN="${SSH_KEYGEN_BIN:-/usr/bin/ssh-keygen}"
SSHD_BIN="${SSHD_BIN:-/usr/sbin/sshd}"
RO_GIT_SERVER_BIN="${RO_GIT_SERVER_BIN:-/usr/local/bin/ro-git-server}"

# Reconcile /users and /teams into /etc/passwd and /etc/group and enforce modes
"$GIT_SYNC_USERS_BIN" >&2

# Ensure OpenSSH host keys exist
"$SSH_KEYGEN_BIN" -A >&2

if [ "$#" -eq 0 ]; then
    "$SSHD_BIN" -e >&2
    exec "$RO_GIT_SERVER_BIN"
fi

exec "$@"
