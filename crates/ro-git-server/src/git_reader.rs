//! Read-only bare Git repository object inspection for `git-worker` and `GitServiceHandler`.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use ro_git_proto::ro_git::v1::{
    CommitFileDiffBuilder, CommitFileDiffView, CommitInfoBuilder, CommitInfoView,
    GetBlobResponseBuilder, GetBlobResponseView, GetCommitResponseBuilder, GetCommitResponseView,
    GetRepositoryResponseBuilder, GetRepositoryResponseView, GetTreeResponseBuilder,
    GetTreeResponseView, ListCommitsResponseBuilder, ListCommitsResponseView, RefInfoBuilder,
    RefInfoView, TreeEntryBuilder, TreeEntryView,
};
use ro_git_proto::{
    format_canonical_path, format_clone_command, format_ssh_url, is_valid_identifier,
    is_valid_revision, is_valid_scope, is_valid_visibility, normalize_repo_path,
    normalize_revision, normalize_ssh_host, strip_git_suffix, tree_kind_from_mode,
    DEFAULT_REVISION, DIFF_STATUS_ADDED, DIFF_STATUS_COPIED, DIFF_STATUS_DELETED,
    DIFF_STATUS_MODIFIED, DIFF_STATUS_RENAMED, DIFF_STATUS_TYPECHANGE, TREE_KIND_DIR,
    TREE_KIND_FILE,
};
use roto_grpc::{GrpcCode, GrpcStatus};

use crate::{can_access_visibility, is_non_symlink_dir, DiscoveredRepository, UserCredentials};

/// Maximum raw blob content returned in `GetBlobResponse.content` before truncation (128 KiB).
pub const MAX_BLOB_BYTES: usize = 128 * 1024;

/// Number of initial bytes inspected for a `0x00` byte to classify a blob as binary.
pub const BINARY_SNIFF_BYTES: usize = 8 * 1024;

/// Default page size for `ListCommits` when `limit == 0`.
pub const DEFAULT_COMMIT_LIMIT: u32 = 50;

/// Maximum page size for `ListCommits`.
pub const MAX_COMMIT_LIMIT: u32 = 200;

/// Maximum per-file unified diff patch length in `CommitFileDiff.patch`.
pub const MAX_FILE_PATCH_BYTES: usize = 16 * 1024;

/// Maximum combined unified diff patch length in `GetCommitResponse.patch`.
pub const MAX_COMMIT_PATCH_BYTES: usize = 64 * 1024;

/// Maximum number of per-file diff records encoded in `GetCommitResponse.files`.
pub const MAX_COMMIT_FILES: usize = 128;

/// Resolved and validated bare repository target on disk.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedRepo {
    pub repo_dir: PathBuf,
    pub info: DiscoveredRepository,
}

/// Git branch or tag reference record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefRecord {
    pub name: String,
    pub full_name: String,
    pub oid: String,
}

/// Single entry in a Git directory tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TreeEntryRecord {
    pub mode: String,
    pub kind: String,
    pub name: String,
    pub path: String,
    pub oid: String,
    pub size: u64,
}

/// Metadata for a single Git commit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitRecord {
    pub oid: String,
    pub parent_oids: Vec<String>,
    pub author_name: String,
    pub author_email: String,
    pub author_time_secs: i64,
    pub committer_name: String,
    pub committer_email: String,
    pub committer_time_secs: i64,
    pub subject: String,
    pub message: String,
}

/// Per-file diff statistics and unified patch within a commit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitFileDiffRecord {
    pub path: String,
    pub old_path: String,
    pub status: String,
    pub additions: u32,
    pub deletions: u32,
    pub patch: String,
}

/// Result of `GetRepository` inspection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepositoryInspection {
    pub repository: DiscoveredRepository,
    pub head_ref: String,
    pub head_oid: String,
    pub resolved_revision: String,
    pub branches: Vec<RefRecord>,
    pub tags: Vec<RefRecord>,
    pub entries: Vec<TreeEntryRecord>,
}

/// Result of `GetTree` inspection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TreeInspection {
    pub revision: String,
    pub tree_oid: String,
    pub path: String,
    pub entries: Vec<TreeEntryRecord>,
}

/// Result of `GetBlob` inspection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlobInspection {
    pub revision: String,
    pub path: String,
    pub oid: String,
    pub size: u64,
    pub is_binary: bool,
    pub truncated: bool,
    pub content: Vec<u8>,
}

/// Result of `ListCommits` inspection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitListInspection {
    pub revision: String,
    pub commits: Vec<CommitRecord>,
    pub has_more: bool,
}

/// Result of `GetCommit` inspection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitDetailInspection {
    pub commit: CommitRecord,
    pub files: Vec<CommitFileDiffRecord>,
    pub total_additions: u32,
    pub total_deletions: u32,
    pub patch: String,
}

/// Error returned by Git object reader operations.
pub type GitReaderError = (GrpcCode, &'static str);

/// Validates `(scope, owner, visibility, name)` and resolves the bare repository path,
/// enforcing symlink rejection, visibility access control, and directory readability.
pub fn validate_and_resolve_repo(
    root_dir: &Path,
    ssh_host: &str,
    creds: &UserCredentials,
    raw_scope: &str,
    raw_owner: &str,
    raw_visibility: &str,
    raw_name: &str,
) -> Result<ValidatedRepo, GitReaderError> {
    let scope = raw_scope.trim();
    let owner = raw_owner.trim();
    let visibility = raw_visibility.trim();
    let name = strip_git_suffix(raw_name.trim());

    if !is_valid_scope(scope)
        || !is_valid_identifier(owner)
        || !is_valid_visibility(visibility)
        || !is_valid_identifier(name)
    {
        return Err((GrpcCode::InvalidArgument, "invalid repository identifier"));
    }

    let scope_dir = root_dir.join(scope);
    let owner_dir = scope_dir.join(owner);
    if !is_non_symlink_dir(&scope_dir) || !is_non_symlink_dir(&owner_dir) {
        return Err((GrpcCode::NotFound, "repository not found"));
    }

    if !can_access_visibility(scope, owner, &owner_dir, visibility, creds) {
        return Err((GrpcCode::NotFound, "repository not found"));
    }

    let vis_dir = owner_dir.join(visibility);
    let repo_dir = vis_dir.join(format!("{name}.git"));
    if !is_non_symlink_dir(&vis_dir) || !is_non_symlink_dir(&repo_dir) {
        return Err((GrpcCode::NotFound, "repository not found"));
    }

    if fs::read_dir(&repo_dir).is_err() {
        return Err((GrpcCode::NotFound, "repository not found"));
    }

    let normalized_host = normalize_ssh_host(ssh_host);
    let canonical_path = format_canonical_path(scope, owner, visibility, name);
    let ssh_url = format_ssh_url(normalized_host, scope, owner, visibility, name);
    let clone_command = format_clone_command(
        normalized_host,
        creds.username.as_deref(),
        scope,
        owner,
        visibility,
        name,
    );

    Ok(ValidatedRepo {
        repo_dir,
        info: DiscoveredRepository {
            scope: scope.to_owned(),
            owner: owner.to_owned(),
            visibility: visibility.to_owned(),
            name: name.to_owned(),
            canonical_path,
            ssh_url,
            clone_command,
        },
    })
}

fn validate_revision_param(raw_revision: &str) -> Result<(&str, bool), GitReaderError> {
    let trimmed = raw_revision.trim();
    let is_empty = trimmed.is_empty();
    let norm = normalize_revision(trimmed);
    if !is_valid_revision(norm) {
        return Err((GrpcCode::InvalidArgument, "invalid git revision"));
    }
    Ok((norm, is_empty))
}

fn validate_path_param(raw_path: &str, allow_empty: bool) -> Result<String, GitReaderError> {
    let Some(norm) = normalize_repo_path(raw_path) else {
        return Err((GrpcCode::InvalidArgument, "invalid repository path"));
    };
    if !allow_empty && norm.is_empty() {
        return Err((GrpcCode::InvalidArgument, "repository path must not be empty"));
    }
    Ok(norm)
}

fn run_git(repo_dir: &Path, args: &[&str]) -> Result<Output, GitReaderError> {
    let mut cmd = Command::new("git");
    cmd.arg("--no-optional-locks")
        .arg(format!("--git-dir={}", repo_dir.display()))
        .args(args)
        .env("LC_ALL", "C")
        .env("GIT_TERMINAL_PROMPT", "0")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd.output()
        .map_err(|_| (GrpcCode::Internal, "failed to execute git subprocess"))
}

fn read_head_symbolic_ref(repo_dir: &Path) -> String {
    let head_path = repo_dir.join("HEAD");
    if let Ok(meta) = fs::symlink_metadata(&head_path) {
        if !meta.file_type().is_symlink() && meta.is_file() {
            if let Ok(contents) = fs::read_to_string(&head_path) {
                let trimmed = contents.trim();
                if let Some(target) = trimmed.strip_prefix("ref:") {
                    let target = target.trim();
                    let short = target.strip_prefix("refs/heads/").unwrap_or(target);
                    return short.to_owned();
                }
                return String::new();
            }
        }
    }
    if let Ok(out) = run_git(repo_dir, &["symbolic-ref", "-q", "--short", "HEAD"]) {
        if out.status.success() {
            if let Ok(s) = std::str::from_utf8(&out.stdout) {
                return s.trim().to_owned();
            }
        }
    }
    String::new()
}

fn resolve_object_oid(repo_dir: &Path, spec: &str) -> Option<String> {
    let out = run_git(repo_dir, &["rev-parse", "--verify", "-q", spec]).ok()?;
    if !out.status.success() {
        return None;
    }
    let s = std::str::from_utf8(&out.stdout).ok()?.trim();
    if s.len() == 40 && s.bytes().all(|b| b.is_ascii_hexdigit()) {
        Some(s.to_owned())
    } else {
        None
    }
}

fn resolve_commit_oid(repo_dir: &Path, rev: &str) -> Option<String> {
    let spec = format!("{rev}^{{commit}}");
    resolve_object_oid(repo_dir, &spec)
}

fn resolve_tree_oid(repo_dir: &Path, rev: &str) -> Option<String> {
    let spec = format!("{rev}^{{tree}}");
    resolve_object_oid(repo_dir, &spec)
}

fn object_type(repo_dir: &Path, spec: &str) -> Option<String> {
    let out = run_git(repo_dir, &["cat-file", "-t", spec]).ok()?;
    if !out.status.success() {
        return None;
    }
    let s = std::str::from_utf8(&out.stdout).ok()?.trim();
    if s.is_empty() {
        None
    } else {
        Some(s.to_owned())
    }
}

fn list_branches(repo_dir: &Path) -> Vec<RefRecord> {
    let Ok(out) = run_git(
        repo_dir,
        &[
            "for-each-ref",
            "--format=%(refname)%00%(objectname)",
            "refs/heads",
        ],
    ) else {
        return Vec::new();
    };
    if !out.status.success() {
        return Vec::new();
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut branches = Vec::new();
    for line in text.lines() {
        let Some((full_name, oid)) = line.split_once('\0') else {
            continue;
        };
        let full_name = full_name.trim();
        let oid = oid.trim();
        if full_name.is_empty() || oid.is_empty() {
            continue;
        }
        let name = full_name
            .strip_prefix("refs/heads/")
            .unwrap_or(full_name)
            .to_owned();
        branches.push(RefRecord {
            name,
            full_name: full_name.to_owned(),
            oid: oid.to_owned(),
        });
    }
    branches.sort_by(|a, b| a.name.cmp(&b.name));
    branches
}

fn list_tags(repo_dir: &Path) -> Vec<RefRecord> {
    let Ok(out) = run_git(
        repo_dir,
        &[
            "for-each-ref",
            "--format=%(refname)%00%(*objectname)%00%(objectname)",
            "refs/tags",
        ],
    ) else {
        return Vec::new();
    };
    if !out.status.success() {
        return Vec::new();
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut tags = Vec::new();
    for line in text.lines() {
        let mut parts = line.splitn(3, '\0');
        let Some(full_name) = parts.next().map(str::trim) else {
            continue;
        };
        let peeled_oid = parts.next().map(str::trim).unwrap_or("");
        let obj_oid = parts.next().map(str::trim).unwrap_or("");
        let oid = if !peeled_oid.is_empty() {
            peeled_oid
        } else {
            obj_oid
        };
        if full_name.is_empty() || oid.is_empty() {
            continue;
        }
        let name = full_name
            .strip_prefix("refs/tags/")
            .unwrap_or(full_name)
            .to_owned();
        tags.push(RefRecord {
            name,
            full_name: full_name.to_owned(),
            oid: oid.to_owned(),
        });
    }
    tags.sort_by(|a, b| a.name.cmp(&b.name));
    tags
}

fn read_tree_entries(
    repo_dir: &Path,
    tree_oid: &str,
    dir_path: &str,
) -> Result<Vec<TreeEntryRecord>, GitReaderError> {
    let out = run_git(repo_dir, &["ls-tree", "-l", "-z", tree_oid])?;
    if !out.status.success() {
        return Err((GrpcCode::NotFound, "tree object not found"));
    }

    let mut entries = Vec::new();
    for raw_record in out.stdout.split(|&b| b == 0).filter(|s| !s.is_empty()) {
        let Some(tab_pos) = raw_record.iter().position(|&b| b == b'\t') else {
            continue;
        };
        let meta_str = std::str::from_utf8(&raw_record[..tab_pos]).unwrap_or("");
        let entry_name = String::from_utf8_lossy(&raw_record[tab_pos + 1..]).into_owned();
        if entry_name.is_empty() {
            continue;
        }

        let mut fields = meta_str.split_whitespace();
        let Some(raw_mode) = fields.next() else {
            continue;
        };
        let Some(_obj_type) = fields.next() else {
            continue;
        };
        let Some(oid) = fields.next() else {
            continue;
        };
        let size_str = fields.next().unwrap_or("-");

        let mode = if raw_mode == "40000" {
            "040000"
        } else {
            raw_mode
        };
        let kind = tree_kind_from_mode(mode).unwrap_or(TREE_KIND_FILE);
        let size = size_str.parse::<u64>().unwrap_or(0);
        let path = if dir_path.is_empty() {
            entry_name.clone()
        } else {
            format!("{dir_path}/{entry_name}")
        };

        entries.push(TreeEntryRecord {
            mode: mode.to_owned(),
            kind: kind.to_owned(),
            name: entry_name,
            path,
            oid: oid.to_owned(),
            size,
        });
    }

    entries.sort_by(|a, b| {
        let a_is_dir = a.kind == TREE_KIND_DIR;
        let b_is_dir = b.kind == TREE_KIND_DIR;
        b_is_dir.cmp(&a_is_dir).then_with(|| a.name.cmp(&b.name))
    });

    Ok(entries)
}

/// Inspects a bare repository for `GetRepository`.
#[allow(clippy::too_many_arguments)]
pub fn inspect_repository(
    root_dir: &Path,
    ssh_host: &str,
    creds: &UserCredentials,
    scope: &str,
    owner: &str,
    visibility: &str,
    name: &str,
    raw_revision: &str,
) -> Result<RepositoryInspection, GitReaderError> {
    let validated =
        validate_and_resolve_repo(root_dir, ssh_host, creds, scope, owner, visibility, name)?;
    let (norm_rev, rev_was_empty) = validate_revision_param(raw_revision)?;
    let repo_dir = &validated.repo_dir;

    let mut head_ref = read_head_symbolic_ref(repo_dir);
    let mut head_oid = resolve_commit_oid(repo_dir, DEFAULT_REVISION).unwrap_or_default();
    let branches = list_branches(repo_dir);
    let tags = list_tags(repo_dir);

    if head_oid.is_empty() {
        if let Some(first_branch) = branches.first() {
            head_oid = first_branch.oid.clone();
            if head_ref.is_empty() {
                head_ref = first_branch.name.clone();
            }
        }
    }

    let (resolved_revision, active_tree_oid) = if !rev_was_empty {
        let Some(tree_oid) = resolve_tree_oid(repo_dir, norm_rev) else {
            return Err((GrpcCode::NotFound, "revision not found"));
        };
        if head_oid.is_empty() {
            if let Some(c_oid) = resolve_commit_oid(repo_dir, norm_rev) {
                head_oid = c_oid;
            }
        }
        (norm_rev.to_owned(), Some(tree_oid))
    } else if !head_oid.is_empty() {
        let rev_label = if !head_ref.is_empty() {
            head_ref.clone()
        } else {
            head_oid.clone()
        };
        let tree_oid = resolve_tree_oid(repo_dir, &head_oid);
        (rev_label, tree_oid)
    } else {
        (String::new(), None)
    };

    let entries = match active_tree_oid {
        Some(ref t_oid) => read_tree_entries(repo_dir, t_oid, "")?,
        None => Vec::new(),
    };

    Ok(RepositoryInspection {
        repository: validated.info,
        head_ref,
        head_oid,
        resolved_revision,
        branches,
        tags,
        entries,
    })
}

fn resolve_active_revision(
    repo_dir: &Path,
    norm_rev: &str,
    rev_was_empty: bool,
) -> Option<String> {
    if resolve_tree_oid(repo_dir, norm_rev).is_some() {
        return Some(norm_rev.to_owned());
    }
    if rev_was_empty {
        let branches = list_branches(repo_dir);
        if let Some(first) = branches.first() {
            return Some(first.name.clone());
        }
    }
    None
}

/// Inspects a directory tree inside a bare repository for `GetTree`.
#[allow(clippy::too_many_arguments)]
pub fn inspect_tree(
    root_dir: &Path,
    ssh_host: &str,
    creds: &UserCredentials,
    scope: &str,
    owner: &str,
    visibility: &str,
    name: &str,
    raw_revision: &str,
    raw_path: &str,
) -> Result<TreeInspection, GitReaderError> {
    let validated =
        validate_and_resolve_repo(root_dir, ssh_host, creds, scope, owner, visibility, name)?;
    let (norm_rev, rev_was_empty) = validate_revision_param(raw_revision)?;
    let path = validate_path_param(raw_path, true)?;
    let repo_dir = &validated.repo_dir;

    let Some(active_rev) = resolve_active_revision(repo_dir, norm_rev, rev_was_empty) else {
        return Err((GrpcCode::NotFound, "revision not found"));
    };

    let tree_oid = if path.is_empty() {
        resolve_tree_oid(repo_dir, &active_rev)
            .ok_or((GrpcCode::NotFound, "tree not found for revision"))?
    } else {
        let spec = format!("{active_rev}:{path}");
        if object_type(repo_dir, &spec).as_deref() != Some("tree") {
            return Err((GrpcCode::NotFound, "directory path not found"));
        }
        resolve_object_oid(repo_dir, &spec)
            .ok_or((GrpcCode::NotFound, "directory path not found"))?
    };

    let entries = read_tree_entries(repo_dir, &tree_oid, &path)?;
    Ok(TreeInspection {
        revision: norm_rev.to_owned(),
        tree_oid,
        path,
        entries,
    })
}

fn read_blob_bytes_bounded(
    repo_dir: &Path,
    blob_oid: &str,
    max_bytes: usize,
) -> Result<(Vec<u8>, bool), GitReaderError> {
    let mut cmd = Command::new("git");
    cmd.arg("--no-optional-locks")
        .arg(format!("--git-dir={}", repo_dir.display()))
        .args(["cat-file", "blob", blob_oid])
        .env("LC_ALL", "C")
        .env("GIT_TERMINAL_PROMPT", "0")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());

    let mut child = cmd
        .spawn()
        .map_err(|_| (GrpcCode::Internal, "failed to spawn git cat-file"))?;

    let mut content = Vec::new();
    if let Some(stdout) = child.stdout.take() {
        let _ = stdout
            .take((max_bytes + 1) as u64)
            .read_to_end(&mut content);
    }

    if content.len() > max_bytes {
        let _ = child.kill();
        let _ = child.wait();
        content.truncate(max_bytes);
        Ok((content, true))
    } else {
        let status = child
            .wait()
            .map_err(|_| (GrpcCode::Internal, "failed waiting for git cat-file"))?;
        if !status.success() {
            return Err((GrpcCode::NotFound, "blob object not found"));
        }
        Ok((content, false))
    }
}

/// Inspects a blob inside a bare repository for `GetBlob`.
#[allow(clippy::too_many_arguments)]
pub fn inspect_blob(
    root_dir: &Path,
    ssh_host: &str,
    creds: &UserCredentials,
    scope: &str,
    owner: &str,
    visibility: &str,
    name: &str,
    raw_revision: &str,
    raw_path: &str,
) -> Result<BlobInspection, GitReaderError> {
    let validated =
        validate_and_resolve_repo(root_dir, ssh_host, creds, scope, owner, visibility, name)?;
    let (norm_rev, rev_was_empty) = validate_revision_param(raw_revision)?;
    let path = validate_path_param(raw_path, false)?;
    let repo_dir = &validated.repo_dir;

    let Some(active_rev) = resolve_active_revision(repo_dir, norm_rev, rev_was_empty) else {
        return Err((GrpcCode::NotFound, "revision not found"));
    };

    let spec = format!("{active_rev}:{path}");
    if object_type(repo_dir, &spec).as_deref() != Some("blob") {
        return Err((GrpcCode::NotFound, "blob path not found"));
    }
    let blob_oid =
        resolve_object_oid(repo_dir, &spec).ok_or((GrpcCode::NotFound, "blob path not found"))?;

    let size_out = run_git(repo_dir, &["cat-file", "-s", &blob_oid])?;
    if !size_out.status.success() {
        return Err((GrpcCode::NotFound, "blob size lookup failed"));
    }
    let size = std::str::from_utf8(&size_out.stdout)
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(0);

    let (content, read_truncated) = read_blob_bytes_bounded(repo_dir, &blob_oid, MAX_BLOB_BYTES)?;
    let truncated = read_truncated || (size > MAX_BLOB_BYTES as u64);
    let sniff_len = content.len().min(BINARY_SNIFF_BYTES);
    let is_binary = content[..sniff_len].contains(&0);

    Ok(BlobInspection {
        revision: norm_rev.to_owned(),
        path,
        oid: blob_oid,
        size,
        is_binary,
        truncated,
        content,
    })
}

const LOG_FORMAT_SPEC: &str =
    "--format=%H%x1f%P%x1f%an%x1f%ae%x1f%at%x1f%cn%x1f%ce%x1f%ct%x1f%s%x1f%B";

fn parse_commit_records(raw_stdout: &[u8]) -> Vec<CommitRecord> {
    let mut commits = Vec::new();
    for record_bytes in raw_stdout.split(|&b| b == 0).filter(|s| !s.is_empty()) {
        let record_str = String::from_utf8_lossy(record_bytes);
        let record_trimmed = record_str.trim_start_matches('\n');
        let mut fields = record_trimmed.splitn(10, '\x1f');
        let Some(oid) = fields.next().map(str::trim) else {
            continue;
        };
        if oid.is_empty() {
            continue;
        }
        let parents_raw = fields.next().unwrap_or("");
        let author_name = fields.next().unwrap_or("").to_owned();
        let author_email = fields.next().unwrap_or("").to_owned();
        let author_time_secs = fields
            .next()
            .and_then(|s| s.trim().parse::<i64>().ok())
            .unwrap_or(0);
        let committer_name = fields.next().unwrap_or("").to_owned();
        let committer_email = fields.next().unwrap_or("").to_owned();
        let committer_time_secs = fields
            .next()
            .and_then(|s| s.trim().parse::<i64>().ok())
            .unwrap_or(0);
        let subject = fields.next().unwrap_or("").to_owned();
        let raw_message = fields.next().unwrap_or("");
        let message = raw_message
            .strip_suffix('\n')
            .unwrap_or(raw_message)
            .to_owned();

        let parent_oids = parents_raw
            .split_whitespace()
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect();

        commits.push(CommitRecord {
            oid: oid.to_owned(),
            parent_oids,
            author_name,
            author_email,
            author_time_secs,
            committer_name,
            committer_email,
            committer_time_secs,
            subject,
            message,
        });
    }
    commits
}

/// Lists paginated commits inside a bare repository for `ListCommits`.
#[allow(clippy::too_many_arguments)]
pub fn inspect_commits(
    root_dir: &Path,
    ssh_host: &str,
    creds: &UserCredentials,
    scope: &str,
    owner: &str,
    visibility: &str,
    name: &str,
    raw_revision: &str,
    raw_path: &str,
    raw_limit: u32,
    offset: u32,
) -> Result<CommitListInspection, GitReaderError> {
    let validated =
        validate_and_resolve_repo(root_dir, ssh_host, creds, scope, owner, visibility, name)?;
    let (norm_rev, rev_was_empty) = validate_revision_param(raw_revision)?;
    let path = validate_path_param(raw_path, true)?;
    let repo_dir = &validated.repo_dir;

    let active_rev = if resolve_commit_oid(repo_dir, norm_rev).is_some() {
        norm_rev.to_owned()
    } else if rev_was_empty {
        let branches = list_branches(repo_dir);
        if let Some(first) = branches.first() {
            first.name.clone()
        } else {
            return Ok(CommitListInspection {
                revision: norm_rev.to_owned(),
                commits: Vec::new(),
                has_more: false,
            });
        }
    } else {
        return Err((GrpcCode::NotFound, "revision not found"));
    };

    let limit = if raw_limit == 0 {
        DEFAULT_COMMIT_LIMIT
    } else {
        raw_limit.min(MAX_COMMIT_LIMIT)
    };
    let fetch_count = (limit as usize) + 1;
    let skip_arg = format!("--skip={offset}");
    let max_count_arg = format!("-n{fetch_count}");

    let mut args = vec![
        "log",
        "-z",
        &skip_arg,
        &max_count_arg,
        LOG_FORMAT_SPEC,
        &active_rev,
    ];
    if !path.is_empty() {
        args.push("--");
        args.push(&path);
    }

    let out = run_git(repo_dir, &args)?;
    if !out.status.success() {
        return Err((GrpcCode::NotFound, "failed to read commit log"));
    }

    let mut commits = parse_commit_records(&out.stdout);
    let has_more = commits.len() > (limit as usize);
    if has_more {
        commits.truncate(limit as usize);
    }

    Ok(CommitListInspection {
        revision: norm_rev.to_owned(),
        commits,
        has_more,
    })
}

fn truncate_utf8_str(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_owned();
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_owned()
}

fn split_unified_diff_patches(full_patch: &str) -> Vec<String> {
    let trimmed = full_patch.trim_start_matches('\n');
    if !trimmed.starts_with("diff --git ") {
        return Vec::new();
    }
    let mut patches = Vec::new();
    let mut start = 0;
    while let Some(pos) = trimmed[start..].find("\ndiff --git ") {
        let end = start + pos + 1;
        patches.push(trimmed[start..end].to_owned());
        start = end;
    }
    patches.push(trimmed[start..].to_owned());
    patches
}

fn parse_diff_name_status_z(raw_bytes: &[u8]) -> Vec<(String, String, String)> {
    let mut tokens = raw_bytes.split(|&b| b == 0).filter(|s| !s.is_empty());
    let mut entries = Vec::new();

    while let Some(status_tok) = tokens.next() {
        let status_str = String::from_utf8_lossy(status_tok);
        let code = status_str.as_bytes().first().copied().unwrap_or(b'M');
        match code {
            b'R' | b'C' => {
                let Some(old_tok) = tokens.next() else {
                    break;
                };
                let Some(new_tok) = tokens.next() else {
                    break;
                };
                let old_path = String::from_utf8_lossy(old_tok).into_owned();
                let new_path = String::from_utf8_lossy(new_tok).into_owned();
                let status = if code == b'R' {
                    DIFF_STATUS_RENAMED
                } else {
                    DIFF_STATUS_COPIED
                };
                entries.push((status.to_owned(), old_path, new_path));
            }
            _ => {
                let Some(path_tok) = tokens.next() else {
                    break;
                };
                let path = String::from_utf8_lossy(path_tok).into_owned();
                let status = match code {
                    b'A' => DIFF_STATUS_ADDED,
                    b'D' => DIFF_STATUS_DELETED,
                    b'T' => DIFF_STATUS_TYPECHANGE,
                    _ => DIFF_STATUS_MODIFIED,
                };
                entries.push((status.to_owned(), String::new(), path));
            }
        }
    }
    entries
}

fn parse_diff_numstat_z(raw_bytes: &[u8]) -> Vec<(u32, u32)> {
    let mut tokens = raw_bytes.split(|&b| b == 0).filter(|s| !s.is_empty());
    let mut stats = Vec::new();

    while let Some(tok) = tokens.next() {
        let s = String::from_utf8_lossy(tok);
        let mut parts = s.splitn(3, '\t');
        let Some(add_str) = parts.next() else {
            continue;
        };
        let Some(del_str) = parts.next() else {
            continue;
        };
        let rest = parts.next().unwrap_or("");
        if rest.is_empty() {
            // Rename or copy in `--numstat -z` consumes two following path tokens
            let _ = tokens.next();
            let _ = tokens.next();
        }
        let additions = add_str.trim().parse::<u32>().unwrap_or(0);
        let deletions = del_str.trim().parse::<u32>().unwrap_or(0);
        stats.push((additions, deletions));
    }
    stats
}

/// Inspects a single commit and its unified diff inside a bare repository for `GetCommit`.
#[allow(clippy::too_many_arguments)]
pub fn inspect_commit(
    root_dir: &Path,
    ssh_host: &str,
    creds: &UserCredentials,
    scope: &str,
    owner: &str,
    visibility: &str,
    name: &str,
    raw_revision: &str,
) -> Result<CommitDetailInspection, GitReaderError> {
    let validated =
        validate_and_resolve_repo(root_dir, ssh_host, creds, scope, owner, visibility, name)?;
    let (norm_rev, rev_was_empty) = validate_revision_param(raw_revision)?;
    let repo_dir = &validated.repo_dir;

    let commit_oid = if let Some(oid) = resolve_commit_oid(repo_dir, norm_rev) {
        oid
    } else if rev_was_empty {
        let branches = list_branches(repo_dir);
        if let Some(first) = branches.first() {
            first.oid.clone()
        } else {
            return Err((GrpcCode::NotFound, "commit not found"));
        }
    } else {
        return Err((GrpcCode::NotFound, "commit not found"));
    };

    let log_out = run_git(
        repo_dir,
        &["log", "-z", "-n1", LOG_FORMAT_SPEC, &commit_oid],
    )?;
    if !log_out.status.success() {
        return Err((GrpcCode::NotFound, "commit not found"));
    }
    let Some(commit) = parse_commit_records(&log_out.stdout).into_iter().next() else {
        return Err((GrpcCode::NotFound, "commit not found"));
    };

    let common_diff_args = [
        "diff-tree",
        "--root",
        "-r",
        "-m",
        "--first-parent",
        "--no-commit-id",
        "-M",
    ];

    let mut ns_args = common_diff_args.to_vec();
    ns_args.extend(["--name-status", "-z", &commit_oid]);
    let ns_out = run_git(repo_dir, &ns_args)?;
    let name_statuses = if ns_out.status.success() {
        parse_diff_name_status_z(&ns_out.stdout)
    } else {
        Vec::new()
    };

    let mut num_args = common_diff_args.to_vec();
    num_args.extend(["--numstat", "-z", &commit_oid]);
    let num_out = run_git(repo_dir, &num_args)?;
    let numstats = if num_out.status.success() {
        parse_diff_numstat_z(&num_out.stdout)
    } else {
        Vec::new()
    };

    let mut patch_args = common_diff_args.to_vec();
    patch_args.extend(["-p", &commit_oid]);
    let patch_out = run_git(repo_dir, &patch_args)?;
    let raw_full_patch = if patch_out.status.success() {
        String::from_utf8_lossy(&patch_out.stdout).into_owned()
    } else {
        String::new()
    };
    let file_patches = split_unified_diff_patches(&raw_full_patch);

    let mut total_additions = 0u32;
    let mut total_deletions = 0u32;
    for &(add, del) in &numstats {
        total_additions = total_additions.saturating_add(add);
        total_deletions = total_deletions.saturating_add(del);
    }

    let mut files = Vec::with_capacity(name_statuses.len().min(MAX_COMMIT_FILES));
    for (idx, (status, old_path, path)) in
        name_statuses.into_iter().take(MAX_COMMIT_FILES).enumerate()
    {
        let (additions, deletions) = numstats.get(idx).copied().unwrap_or((0, 0));
        let file_patch = file_patches
            .get(idx)
            .map(|p| truncate_utf8_str(p, MAX_FILE_PATCH_BYTES))
            .unwrap_or_default();
        files.push(CommitFileDiffRecord {
            path,
            old_path,
            status,
            additions,
            deletions,
            patch: file_patch,
        });
    }

    let patch = truncate_utf8_str(&raw_full_patch, MAX_COMMIT_PATCH_BYTES);

    Ok(CommitDetailInspection {
        commit,
        files,
        total_additions,
        total_deletions,
        patch,
    })
}

fn write_ref_record(b: &mut RefInfoBuilder<'_>, r: &RefRecord) {
    b.write_oid(&r.oid)
        .write_full_name(&r.full_name)
        .write_name(&r.name);
}

fn write_tree_entry_record(b: &mut TreeEntryBuilder<'_>, e: &TreeEntryRecord) {
    b.write_size(e.size)
        .write_oid(&e.oid)
        .write_path(&e.path)
        .write_name(&e.name)
        .write_kind(&e.kind)
        .write_mode(&e.mode);
}

fn write_commit_record(b: &mut CommitInfoBuilder<'_>, c: &CommitRecord) -> bool {
    b.write_message(&c.message)
        .write_subject(&c.subject)
        .write_committer_time_secs(c.committer_time_secs)
        .write_committer_email(&c.committer_email)
        .write_committer_name(&c.committer_name)
        .write_author_time_secs(c.author_time_secs)
        .write_author_email(&c.author_email)
        .write_author_name(&c.author_name);
    for parent in c.parent_oids.iter().rev() {
        b.write_parent_oids(parent);
        if b.check().is_err() {
            return false;
        }
    }
    b.write_oid(&c.oid);
    b.check().is_ok()
}

fn write_file_diff_record(b: &mut CommitFileDiffBuilder<'_>, f: &CommitFileDiffRecord) {
    b.write_patch(&f.patch)
        .write_deletions(f.deletions)
        .write_additions(f.additions)
        .write_status(&f.status)
        .write_old_path(&f.old_path)
        .write_path(&f.path);
}

impl RepositoryInspection {
    /// Encodes `RepositoryInspection` into `GetRepositoryResponseBuilder` in reverse tag order.
    pub fn encode_into(&self, resp: &mut GetRepositoryResponseBuilder<'_>) -> bool {
        for entry in self.entries.iter().rev() {
            resp.write_entries(|e| write_tree_entry_record(e, entry));
            if resp.check().is_err() {
                return false;
            }
        }
        for tag in self.tags.iter().rev() {
            resp.write_tags(|t| write_ref_record(t, tag));
            if resp.check().is_err() {
                return false;
            }
        }
        for branch in self.branches.iter().rev() {
            resp.write_branches(|b| write_ref_record(b, branch));
            if resp.check().is_err() {
                return false;
            }
        }
        resp.write_resolved_revision(&self.resolved_revision)
            .write_head_oid(&self.head_oid)
            .write_head_ref(&self.head_ref)
            .write_repository(|r| {
                r.write_clone_command(&self.repository.clone_command)
                    .write_ssh_url(&self.repository.ssh_url)
                    .write_canonical_path(&self.repository.canonical_path)
                    .write_name(&self.repository.name)
                    .write_visibility(&self.repository.visibility)
                    .write_owner(&self.repository.owner)
                    .write_scope(&self.repository.scope);
            });
        resp.check().is_ok()
    }
}

impl TreeInspection {
    /// Encodes `TreeInspection` into `GetTreeResponseBuilder` in reverse tag order.
    pub fn encode_into(&self, resp: &mut GetTreeResponseBuilder<'_>) -> bool {
        for entry in self.entries.iter().rev() {
            resp.write_entries(|e| write_tree_entry_record(e, entry));
            if resp.check().is_err() {
                return false;
            }
        }
        resp.write_path(&self.path)
            .write_tree_oid(&self.tree_oid)
            .write_revision(&self.revision);
        resp.check().is_ok()
    }
}

impl BlobInspection {
    /// Encodes `BlobInspection` into `GetBlobResponseBuilder` in reverse tag order.
    pub fn encode_into(&self, resp: &mut GetBlobResponseBuilder<'_>) -> bool {
        resp.write_content(&self.content)
            .write_truncated(self.truncated)
            .write_is_binary(self.is_binary)
            .write_size(self.size)
            .write_oid(&self.oid)
            .write_path(&self.path)
            .write_revision(&self.revision);
        resp.check().is_ok()
    }
}

impl CommitListInspection {
    /// Encodes `CommitListInspection` into `ListCommitsResponseBuilder` in reverse tag order.
    pub fn encode_into(&self, resp: &mut ListCommitsResponseBuilder<'_>) -> bool {
        resp.write_has_more(self.has_more);
        for commit in self.commits.iter().rev() {
            let mut ok = true;
            resp.write_commits(|c| {
                ok = write_commit_record(c, commit);
            });
            if !ok || resp.check().is_err() {
                return false;
            }
        }
        resp.write_revision(&self.revision);
        resp.check().is_ok()
    }
}

impl CommitDetailInspection {
    /// Encodes `CommitDetailInspection` into `GetCommitResponseBuilder` in reverse tag order.
    pub fn encode_into(&self, resp: &mut GetCommitResponseBuilder<'_>) -> bool {
        resp.write_patch(&self.patch)
            .write_total_deletions(self.total_deletions)
            .write_total_additions(self.total_additions);
        for file in self.files.iter().rev() {
            resp.write_files(|f| write_file_diff_record(f, file));
            if resp.check().is_err() {
                return false;
            }
        }
        let mut commit_ok = true;
        resp.write_commit(|c| {
            commit_ok = write_commit_record(c, &self.commit);
        });
        commit_ok && resp.check().is_ok()
    }
}

fn decode_ref_view(v: RefInfoView<'_>) -> RefRecord {
    RefRecord {
        name: v.name().unwrap_or("").to_owned(),
        full_name: v.full_name().unwrap_or("").to_owned(),
        oid: v.oid().unwrap_or("").to_owned(),
    }
}

fn decode_tree_entry_view(v: TreeEntryView<'_>) -> TreeEntryRecord {
    TreeEntryRecord {
        mode: v.mode().unwrap_or("").to_owned(),
        kind: v.kind().unwrap_or("").to_owned(),
        name: v.name().unwrap_or("").to_owned(),
        path: v.path().unwrap_or("").to_owned(),
        oid: v.oid().unwrap_or("").to_owned(),
        size: v.size().unwrap_or(0),
    }
}

fn decode_commit_view(v: CommitInfoView<'_>) -> Result<CommitRecord, GrpcStatus<'static>> {
    let mut parent_oids = Vec::new();
    for p in v.parent_oids() {
        let s = p.map_err(|_| GrpcStatus::internal("invalid parent_oid in WorkerResponse"))?;
        parent_oids.push(s.to_owned());
    }
    Ok(CommitRecord {
        oid: v.oid().unwrap_or("").to_owned(),
        parent_oids,
        author_name: v.author_name().unwrap_or("").to_owned(),
        author_email: v.author_email().unwrap_or("").to_owned(),
        author_time_secs: v.author_time_secs().unwrap_or(0),
        committer_name: v.committer_name().unwrap_or("").to_owned(),
        committer_email: v.committer_email().unwrap_or("").to_owned(),
        committer_time_secs: v.committer_time_secs().unwrap_or(0),
        subject: v.subject().unwrap_or("").to_owned(),
        message: v.message().unwrap_or("").to_owned(),
    })
}

fn decode_file_diff_view(v: CommitFileDiffView<'_>) -> CommitFileDiffRecord {
    CommitFileDiffRecord {
        path: v.path().unwrap_or("").to_owned(),
        old_path: v.old_path().unwrap_or("").to_owned(),
        status: v.status().unwrap_or("").to_owned(),
        additions: v.additions().unwrap_or(0),
        deletions: v.deletions().unwrap_or(0),
        patch: v.patch().unwrap_or("").to_owned(),
    }
}

/// Copies a decoded `GetRepositoryResponseView` from the worker into `GetRepositoryResponseBuilder`.
pub fn copy_get_repository_response(
    view: GetRepositoryResponseView<'_>,
    resp: &mut GetRepositoryResponseBuilder<'_>,
) -> Result<(), GrpcStatus<'static>> {
    let repo_view = view
        .repository()
        .map_err(|_| GrpcStatus::internal("invalid repository in WorkerResponse"))?
        .ok_or_else(|| GrpcStatus::internal("missing repository in WorkerResponse"))?;

    let mut branches = Vec::new();
    for item in view.branches() {
        let v = item.map_err(|_| GrpcStatus::internal("invalid branch in WorkerResponse"))?;
        branches.push(decode_ref_view(v));
    }

    let mut tags = Vec::new();
    for item in view.tags() {
        let v = item.map_err(|_| GrpcStatus::internal("invalid tag in WorkerResponse"))?;
        tags.push(decode_ref_view(v));
    }

    let mut entries = Vec::new();
    for item in view.entries() {
        let v = item.map_err(|_| GrpcStatus::internal("invalid tree entry in WorkerResponse"))?;
        entries.push(decode_tree_entry_view(v));
    }

    let inspection = RepositoryInspection {
        repository: DiscoveredRepository {
            scope: repo_view.scope().unwrap_or("").to_owned(),
            owner: repo_view.owner().unwrap_or("").to_owned(),
            visibility: repo_view.visibility().unwrap_or("").to_owned(),
            name: repo_view.name().unwrap_or("").to_owned(),
            canonical_path: repo_view.canonical_path().unwrap_or("").to_owned(),
            ssh_url: repo_view.ssh_url().unwrap_or("").to_owned(),
            clone_command: repo_view.clone_command().unwrap_or("").to_owned(),
        },
        head_ref: view.head_ref().unwrap_or("").to_owned(),
        head_oid: view.head_oid().unwrap_or("").to_owned(),
        resolved_revision: view.resolved_revision().unwrap_or("").to_owned(),
        branches,
        tags,
        entries,
    };

    if !inspection.encode_into(resp) {
        return Err(GrpcStatus::resource_exhausted("response buffer exhausted"));
    }
    Ok(())
}

/// Copies a decoded `GetTreeResponseView` from the worker into `GetTreeResponseBuilder`.
pub fn copy_get_tree_response(
    view: GetTreeResponseView<'_>,
    resp: &mut GetTreeResponseBuilder<'_>,
) -> Result<(), GrpcStatus<'static>> {
    let mut entries = Vec::new();
    for item in view.entries() {
        let v = item.map_err(|_| GrpcStatus::internal("invalid tree entry in WorkerResponse"))?;
        entries.push(decode_tree_entry_view(v));
    }
    let inspection = TreeInspection {
        revision: view.revision().unwrap_or("").to_owned(),
        tree_oid: view.tree_oid().unwrap_or("").to_owned(),
        path: view.path().unwrap_or("").to_owned(),
        entries,
    };
    if !inspection.encode_into(resp) {
        return Err(GrpcStatus::resource_exhausted("response buffer exhausted"));
    }
    Ok(())
}

/// Copies a decoded `GetBlobResponseView` from the worker into `GetBlobResponseBuilder`.
pub fn copy_get_blob_response(
    view: GetBlobResponseView<'_>,
    resp: &mut GetBlobResponseBuilder<'_>,
) -> Result<(), GrpcStatus<'static>> {
    resp.write_content(view.content().unwrap_or(&[]))
        .write_truncated(view.truncated().unwrap_or(false))
        .write_is_binary(view.is_binary().unwrap_or(false))
        .write_size(view.size().unwrap_or(0))
        .write_oid(view.oid().unwrap_or(""))
        .write_path(view.path().unwrap_or(""))
        .write_revision(view.revision().unwrap_or(""));
    resp.check()
        .map_err(|_| GrpcStatus::resource_exhausted("response buffer exhausted"))?;
    Ok(())
}

/// Copies a decoded `ListCommitsResponseView` from the worker into `ListCommitsResponseBuilder`.
pub fn copy_list_commits_response(
    view: ListCommitsResponseView<'_>,
    resp: &mut ListCommitsResponseBuilder<'_>,
) -> Result<(), GrpcStatus<'static>> {
    let mut commits = Vec::new();
    for item in view.commits() {
        let v = item.map_err(|_| GrpcStatus::internal("invalid commit in WorkerResponse"))?;
        commits.push(decode_commit_view(v)?);
    }
    let inspection = CommitListInspection {
        revision: view.revision().unwrap_or("").to_owned(),
        commits,
        has_more: view.has_more().unwrap_or(false),
    };
    if !inspection.encode_into(resp) {
        return Err(GrpcStatus::resource_exhausted("response buffer exhausted"));
    }
    Ok(())
}

/// Copies a decoded `GetCommitResponseView` from the worker into `GetCommitResponseBuilder`.
pub fn copy_get_commit_response(
    view: GetCommitResponseView<'_>,
    resp: &mut GetCommitResponseBuilder<'_>,
) -> Result<(), GrpcStatus<'static>> {
    let commit_view = view
        .commit()
        .map_err(|_| GrpcStatus::internal("invalid commit in WorkerResponse"))?
        .ok_or_else(|| GrpcStatus::internal("missing commit in WorkerResponse"))?;
    let commit = decode_commit_view(commit_view)?;

    let mut files = Vec::new();
    for item in view.files() {
        let v = item.map_err(|_| GrpcStatus::internal("invalid file diff in WorkerResponse"))?;
        files.push(decode_file_diff_view(v));
    }

    let inspection = CommitDetailInspection {
        commit,
        files,
        total_additions: view.total_additions().unwrap_or(0),
        total_deletions: view.total_deletions().unwrap_or(0),
        patch: view.patch().unwrap_or("").to_owned(),
    };
    if !inspection.encode_into(resp) {
        return Err(GrpcStatus::resource_exhausted("response buffer exhausted"));
    }
    Ok(())
}

fn push_repository_info_json(out: &mut String, r: ro_git_proto::v1::RepositoryInfoView<'_>) {
    out.push_str("{\"scope\":");
    crate::push_json_escaped(out, r.scope().unwrap_or(""));
    out.push_str(",\"owner\":");
    crate::push_json_escaped(out, r.owner().unwrap_or(""));
    out.push_str(",\"visibility\":");
    crate::push_json_escaped(out, r.visibility().unwrap_or(""));
    out.push_str(",\"name\":");
    crate::push_json_escaped(out, r.name().unwrap_or(""));
    out.push_str(",\"canonical_path\":");
    crate::push_json_escaped(out, r.canonical_path().unwrap_or(""));
    out.push_str(",\"ssh_url\":");
    crate::push_json_escaped(out, r.ssh_url().unwrap_or(""));
    out.push_str(",\"clone_command\":");
    crate::push_json_escaped(out, r.clone_command().unwrap_or(""));
    out.push('}');
}

fn push_tree_entry_json(out: &mut String, entry: TreeEntryView<'_>) {
    use std::fmt::Write;
    out.push_str("{\"mode\":");
    crate::push_json_escaped(out, entry.mode().unwrap_or(""));
    out.push_str(",\"kind\":");
    crate::push_json_escaped(out, entry.kind().unwrap_or(""));
    out.push_str(",\"name\":");
    crate::push_json_escaped(out, entry.name().unwrap_or(""));
    out.push_str(",\"path\":");
    crate::push_json_escaped(out, entry.path().unwrap_or(""));
    out.push_str(",\"oid\":");
    crate::push_json_escaped(out, entry.oid().unwrap_or(""));
    let _ = write!(out, ",\"size\":{}}}", entry.size().unwrap_or(0));
}

fn push_commit_info_json(out: &mut String, commit: CommitInfoView<'_>) {
    use std::fmt::Write;
    out.push_str("{\"oid\":");
    crate::push_json_escaped(out, commit.oid().unwrap_or(""));
    out.push_str(",\"parent_oids\":[");
    let mut first = true;
    for p in commit.parent_oids().flatten() {
        if !first {
            out.push(',');
        }
        first = false;
        crate::push_json_escaped(out, p);
    }
    out.push_str("],\"author_name\":");
    crate::push_json_escaped(out, commit.author_name().unwrap_or(""));
    out.push_str(",\"author_email\":");
    crate::push_json_escaped(out, commit.author_email().unwrap_or(""));
    let _ = write!(
        out,
        ",\"author_time_secs\":{},\"committer_name\":",
        commit.author_time_secs().unwrap_or(0)
    );
    crate::push_json_escaped(out, commit.committer_name().unwrap_or(""));
    out.push_str(",\"committer_email\":");
    crate::push_json_escaped(out, commit.committer_email().unwrap_or(""));
    let _ = write!(
        out,
        ",\"committer_time_secs\":{},\"subject\":",
        commit.committer_time_secs().unwrap_or(0)
    );
    crate::push_json_escaped(out, commit.subject().unwrap_or(""));
    out.push_str(",\"message\":");
    crate::push_json_escaped(out, commit.message().unwrap_or(""));
    out.push('}');
}

/// Encodes `GetRepositoryResponseView` as UTF-8 JSON bytes.
#[must_use]
pub fn encode_get_repository_json(view: GetRepositoryResponseView<'_>) -> Vec<u8> {
    let mut json = String::with_capacity(512);
    json.push_str("{\"repository\":");
    if let Ok(Some(r)) = view.repository() {
        push_repository_info_json(&mut json, r);
    } else {
        json.push_str("null");
    }
    json.push_str(",\"head_ref\":");
    crate::push_json_escaped(&mut json, view.head_ref().unwrap_or(""));
    json.push_str(",\"head_oid\":");
    crate::push_json_escaped(&mut json, view.head_oid().unwrap_or(""));
    json.push_str(",\"resolved_revision\":");
    crate::push_json_escaped(&mut json, view.resolved_revision().unwrap_or(""));

    json.push_str(",\"branches\":[");
    let mut first = true;
    for b in view.branches().flatten() {
        if !first {
            json.push(',');
        }
        first = false;
        json.push_str("{\"name\":");
        crate::push_json_escaped(&mut json, b.name().unwrap_or(""));
        json.push_str(",\"full_name\":");
        crate::push_json_escaped(&mut json, b.full_name().unwrap_or(""));
        json.push_str(",\"oid\":");
        crate::push_json_escaped(&mut json, b.oid().unwrap_or(""));
        json.push('}');
    }

    json.push_str("],\"tags\":[");
    let mut first = true;
    for t in view.tags().flatten() {
        if !first {
            json.push(',');
        }
        first = false;
        json.push_str("{\"name\":");
        crate::push_json_escaped(&mut json, t.name().unwrap_or(""));
        json.push_str(",\"full_name\":");
        crate::push_json_escaped(&mut json, t.full_name().unwrap_or(""));
        json.push_str(",\"oid\":");
        crate::push_json_escaped(&mut json, t.oid().unwrap_or(""));
        json.push('}');
    }

    json.push_str("],\"entries\":[");
    let mut first = true;
    for e in view.entries().flatten() {
        if !first {
            json.push(',');
        }
        first = false;
        push_tree_entry_json(&mut json, e);
    }
    json.push_str("]}");
    json.into_bytes()
}

/// Encodes `GetTreeResponseView` as UTF-8 JSON bytes.
#[must_use]
pub fn encode_get_tree_json(view: GetTreeResponseView<'_>) -> Vec<u8> {
    let mut json = String::with_capacity(512);
    json.push_str("{\"revision\":");
    crate::push_json_escaped(&mut json, view.revision().unwrap_or(""));
    json.push_str(",\"tree_oid\":");
    crate::push_json_escaped(&mut json, view.tree_oid().unwrap_or(""));
    json.push_str(",\"path\":");
    crate::push_json_escaped(&mut json, view.path().unwrap_or(""));
    json.push_str(",\"entries\":[");
    let mut first = true;
    for e in view.entries().flatten() {
        if !first {
            json.push(',');
        }
        first = false;
        push_tree_entry_json(&mut json, e);
    }
    json.push_str("]}");
    json.into_bytes()
}

/// Encodes `GetBlobResponseView` as UTF-8 JSON bytes.
#[must_use]
pub fn encode_get_blob_json(view: GetBlobResponseView<'_>) -> Vec<u8> {
    use std::fmt::Write;
    let mut json = String::with_capacity(512);
    json.push_str("{\"revision\":");
    crate::push_json_escaped(&mut json, view.revision().unwrap_or(""));
    json.push_str(",\"path\":");
    crate::push_json_escaped(&mut json, view.path().unwrap_or(""));
    json.push_str(",\"oid\":");
    crate::push_json_escaped(&mut json, view.oid().unwrap_or(""));
    let _ = write!(
        json,
        ",\"size\":{},\"is_binary\":{},\"truncated\":{},\"content\":",
        view.size().unwrap_or(0),
        if view.is_binary().unwrap_or(false) {
            "true"
        } else {
            "false"
        },
        if view.truncated().unwrap_or(false) {
            "true"
        } else {
            "false"
        }
    );
    let content_lossy = String::from_utf8_lossy(view.content().unwrap_or(&[]));
    crate::push_json_escaped(&mut json, &content_lossy);
    json.push('}');
    json.into_bytes()
}

/// Encodes `ListCommitsResponseView` as UTF-8 JSON bytes.
#[must_use]
pub fn encode_list_commits_json(view: ListCommitsResponseView<'_>) -> Vec<u8> {
    let mut json = String::with_capacity(512);
    json.push_str("{\"revision\":");
    crate::push_json_escaped(&mut json, view.revision().unwrap_or(""));
    json.push_str(",\"commits\":[");
    let mut first = true;
    for c in view.commits().flatten() {
        if !first {
            json.push(',');
        }
        first = false;
        push_commit_info_json(&mut json, c);
    }
    json.push_str("],\"has_more\":");
    json.push_str(if view.has_more().unwrap_or(false) {
        "true"
    } else {
        "false"
    });
    json.push('}');
    json.into_bytes()
}

/// Encodes `GetCommitResponseView` as UTF-8 JSON bytes.
#[must_use]
pub fn encode_get_commit_json(view: GetCommitResponseView<'_>) -> Vec<u8> {
    use std::fmt::Write;
    let mut json = String::with_capacity(512);
    json.push_str("{\"commit\":");
    if let Ok(Some(c)) = view.commit() {
        push_commit_info_json(&mut json, c);
    } else {
        json.push_str("null");
    }
    json.push_str(",\"files\":[");
    let mut first = true;
    for f in view.files().flatten() {
        if !first {
            json.push(',');
        }
        first = false;
        json.push_str("{\"path\":");
        crate::push_json_escaped(&mut json, f.path().unwrap_or(""));
        json.push_str(",\"old_path\":");
        crate::push_json_escaped(&mut json, f.old_path().unwrap_or(""));
        json.push_str(",\"status\":");
        crate::push_json_escaped(&mut json, f.status().unwrap_or(""));
        let _ = write!(
            json,
            ",\"additions\":{},\"deletions\":{},\"patch\":",
            f.additions().unwrap_or(0),
            f.deletions().unwrap_or(0)
        );
        crate::push_json_escaped(&mut json, f.patch().unwrap_or(""));
        json.push('}');
    }
    let _ = write!(
        json,
        "],\"total_additions\":{},\"total_deletions\":{},\"patch\":",
        view.total_additions().unwrap_or(0),
        view.total_deletions().unwrap_or(0)
    );
    crate::push_json_escaped(&mut json, view.patch().unwrap_or(""));
    json.push('}');
    json.into_bytes()
}

