#!/usr/bin/env bash
set -euo pipefail

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "Error: Not inside a git repository." >&2
    exit 1
fi

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

if ! git show-ref --quiet --heads issues-data; then
    echo "Creating orphan branch 'issues-data'..."
    EMPTY_TREE=$(git hash-object -t tree /dev/null)
    COMMIT_HASH=$(git commit-tree "$EMPTY_TREE" -m "issue: initialize issues-data branch")
    git branch issues-data "$COMMIT_HASH"
fi

if git worktree list | grep -q "[ /]issues\b"; then
    git worktree repair issues >/dev/null 2>&1 || true
    echo "issues/ worktree already mounted."
elif [ -d "issues" ]; then
    git worktree repair issues >/dev/null 2>&1 || true
    echo "issues/ directory already exists."
else
    echo "Mounting issues/ worktree on issues-data branch..."
    git worktree add issues issues-data
    mkdir -p issues/backlog issues/bugs issues/milestone_0
fi

echo "Issue tracker ready at $REPO_ROOT/issues"
