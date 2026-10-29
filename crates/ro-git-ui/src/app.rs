use crate::{
    available_owners, build_bearer_token_from_signature, build_blob_api_url, build_commit_api_url,
    build_commits_api_url, build_repository_api_url, build_sign_in_challenge, build_tree_api_url,
    copy_button_label, decode_auth_status_response, decode_get_blob_response,
    decode_get_commit_response, decode_get_repository_response, decode_get_tree_response,
    decode_list_commits_response, decode_repositories_response, filter_and_group_repositories,
    find_readme_entry, format_authorization_header, parse_app_route, render_blob_view,
    render_clone_protocol_toggle, render_commit_detail_view, render_commits_view,
    render_repository_header, render_tree_view, verify_auth_status_for_user, AppRoute, AuthStatus,
    BlobViewMode, BlobViewModel, CloneProtocol, CommitDetailModel, CommitListModel, CopyTarget,
    RepoFilter, RepositoriesSnapshot, RepositoryGroup, RepositoryItem, RepositoryOverviewModel,
    ScopeFilter, SignInChallenge, TreeViewModel, VisibilityFilter, COMMITS_PAGE_SIZE,
    DEFAULT_HTTPS_HOST, DEFAULT_SSH_HOST, DEFAULT_TTL_SECS, LOCAL_STORAGE_TOKEN_KEY, TTL_OPTIONS,
};
use gloo_timers::callback::Timeout;
use js_sys::{Date, Uint8Array};
use ro_git_proto::{API_AUTH_STATUS_PATH, API_REPOSITORIES_PATH, DEFAULT_REVISION};
use std::cell::Cell;
use std::rc::Rc;
use wasm_bindgen::closure::Closure;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::{spawn_local, JsFuture};
use web_sys::{
    HtmlInputElement, HtmlSelectElement, HtmlTextAreaElement, PopStateEvent, Request, RequestInit,
    Response, Storage,
};
use yew::prelude::*;

fn browser_local_storage() -> Option<Storage> {
    web_sys::window()?.local_storage().ok().flatten()
}

fn load_stored_token() -> Option<String> {
    let storage = browser_local_storage()?;
    let raw = storage.get_item(LOCAL_STORAGE_TOKEN_KEY).ok().flatten()?;
    let trimmed = raw.trim().to_owned();
    (!trimmed.is_empty()).then_some(trimmed)
}

fn save_stored_token(token: &str) {
    if let Some(storage) = browser_local_storage() {
        let _ = storage.set_item(LOCAL_STORAGE_TOKEN_KEY, token.trim());
    }
}

fn clear_stored_token() {
    if let Some(storage) = browser_local_storage() {
        let _ = storage.remove_item(LOCAL_STORAGE_TOKEN_KEY);
    }
}

fn current_unix_secs() -> u64 {
    let ms = Date::now();
    if ms.is_finite() && ms > 0.0 {
        (ms / 1000.0) as u64
    } else {
        1_700_000_000
    }
}

fn copy_text_to_clipboard(text: String) {
    if let Some(window) = web_sys::window() {
        let clipboard = window.navigator().clipboard();
        let _ = clipboard.write_text(&text);
    }
}

fn current_browser_route() -> AppRoute {
    let Some(window) = web_sys::window() else {
        return AppRoute::Index;
    };
    let location = window.location();
    let pathname = location.pathname().unwrap_or_else(|_| "/".to_owned());
    let search = location.search().unwrap_or_default();
    let combined = format!("{pathname}{search}");
    parse_app_route(&combined).unwrap_or(AppRoute::Index)
}

fn push_browser_route(route: &AppRoute) {
    if let Some(window) = web_sys::window() {
        if let Ok(history) = window.history() {
            let path = route.to_path();
            let _ = history.push_state_with_url(&JsValue::NULL, "", Some(&path));
        }
    }
}

async fn fetch_protobuf_bytes(path: &str, token: Option<&str>) -> Result<Vec<u8>, String> {
    let window = web_sys::window().ok_or_else(|| "Browser window unavailable.".to_owned())?;
    let init = RequestInit::new();
    init.set_method("GET");

    let request = Request::new_with_str_and_init(path, &init)
        .map_err(|e| format!("Failed to build request for {path}: {e:?}"))?;
    let headers = request.headers();
    let _ = headers.set("Accept", "application/x-protobuf");

    if let Some(auth_value) = token.and_then(format_authorization_header) {
        let _ = headers.set("Authorization", &auth_value);
    }

    let resp_val = JsFuture::from(window.fetch_with_request(&request))
        .await
        .map_err(|e| format!("Network request to {path} failed: {e:?}"))?;
    let resp: Response = resp_val
        .dyn_into()
        .map_err(|_| format!("Invalid fetch response object for {path}"))?;

    if !resp.ok() {
        return Err(format!(
            "Server returned HTTP {} for {path}",
            resp.status()
        ));
    }

    let buf_promise = resp
        .array_buffer()
        .map_err(|e| format!("Failed to read response body for {path}: {e:?}"))?;
    let buf_val = JsFuture::from(buf_promise)
        .await
        .map_err(|e| format!("Failed to await response buffer for {path}: {e:?}"))?;

    Ok(Uint8Array::new(&buf_val).to_vec())
}

async fn fetch_auth_status(token: Option<&str>) -> Result<AuthStatus, String> {
    let bytes = fetch_protobuf_bytes(API_AUTH_STATUS_PATH, token).await?;
    decode_auth_status_response(&bytes)
}

async fn fetch_repositories(token: Option<&str>) -> Result<RepositoriesSnapshot, String> {
    let bytes = fetch_protobuf_bytes(API_REPOSITORIES_PATH, token).await?;
    decode_repositories_response(&bytes)
}

async fn fetch_repository_overview(
    scope: &str,
    owner: &str,
    visibility: &str,
    name: &str,
    revision: Option<&str>,
    token: Option<&str>,
) -> Result<RepositoryOverviewModel, String> {
    let url = build_repository_api_url(scope, owner, visibility, name, revision);
    let bytes = fetch_protobuf_bytes(&url, token).await?;
    decode_get_repository_response(&bytes)
}

async fn fetch_tree_view(
    scope: &str,
    owner: &str,
    visibility: &str,
    name: &str,
    revision: &str,
    path: &str,
    token: Option<&str>,
) -> Result<TreeViewModel, String> {
    let url = build_tree_api_url(scope, owner, visibility, name, revision, path);
    let bytes = fetch_protobuf_bytes(&url, token).await?;
    decode_get_tree_response(&bytes)
}

async fn fetch_blob_view(
    scope: &str,
    owner: &str,
    visibility: &str,
    name: &str,
    revision: &str,
    path: &str,
    token: Option<&str>,
) -> Result<BlobViewModel, String> {
    let url = build_blob_api_url(scope, owner, visibility, name, revision, path);
    let bytes = fetch_protobuf_bytes(&url, token).await?;
    decode_get_blob_response(&bytes)
}

#[allow(clippy::too_many_arguments)]
async fn fetch_commit_list(
    scope: &str,
    owner: &str,
    visibility: &str,
    name: &str,
    revision: &str,
    path: &str,
    limit: u32,
    offset: u32,
    token: Option<&str>,
) -> Result<CommitListModel, String> {
    let url = build_commits_api_url(scope, owner, visibility, name, revision, path, limit, offset);
    let bytes = fetch_protobuf_bytes(&url, token).await?;
    decode_list_commits_response(&bytes)
}

async fn fetch_commit_detail(
    scope: &str,
    owner: &str,
    visibility: &str,
    name: &str,
    revision: &str,
    token: Option<&str>,
) -> Result<CommitDetailModel, String> {
    let url = build_commit_api_url(scope, owner, visibility, name, revision);
    let bytes = fetch_protobuf_bytes(&url, token).await?;
    decode_get_commit_response(&bytes)
}

fn render_header(
    auth_status: &AuthStatus,
    loading: bool,
    on_navigate: &Callback<AppRoute>,
    on_refresh: Callback<MouseEvent>,
    on_open_sign_in: Callback<MouseEvent>,
    on_sign_out: Callback<MouseEvent>,
) -> Html {
    let on_brand_click = {
        let on_navigate = on_navigate.clone();
        Callback::from(move |e: MouseEvent| {
            if !e.ctrl_key() && !e.meta_key() && !e.shift_key() && !e.alt_key() && e.button() == 0 {
                e.prevent_default();
                on_navigate.emit(AppRoute::Index);
            }
        })
    };

    html! {
        <header class="app-header">
            <div class="brand-block">
                <div class="brand-title-row">
                    <h1 class="brand-title">
                        <a href="/" class="brand-link" onclick={on_brand_click}>{ "ro-git" }</a>
                    </h1>
                    <span class="host-pill" title="Configured SSH host">
                        { format!("ssh://{}", auth_status.ssh_host) }
                    </span>
                </div>
                <p class="brand-subtitle">{ "Read-Only Git Repository Browser" }</p>
            </div>

            <div class="auth-bar">
                <span
                    class={classes!(
                        "auth-status-badge",
                        if auth_status.authenticated { "auth-authenticated" } else { "auth-anonymous" }
                    )}
                >
                    { auth_status.header_label() }
                </span>
                <button
                    type="button"
                    class="btn btn-secondary"
                    onclick={on_refresh}
                    disabled={loading}
                >
                    { if loading { "Refreshing..." } else { "Refresh" } }
                </button>
                if auth_status.authenticated {
                    <button
                        type="button"
                        class="btn btn-danger"
                        onclick={on_sign_out}
                    >
                        { "Sign Out" }
                    </button>
                } else {
                    <button
                        type="button"
                        class="btn btn-primary"
                        onclick={on_open_sign_in}
                    >
                        { "Sign In with SSH Key" }
                    </button>
                }
            </div>
        </header>
    }
}

#[allow(clippy::too_many_arguments)]
fn render_filter_bar(
    filter: &RepoFilter,
    owners: &[String],
    matched_count: usize,
    total_count: usize,
    on_query_input: Callback<InputEvent>,
    on_scope_change: Callback<Event>,
    on_owner_change: Callback<Event>,
    on_visibility_change: Callback<Event>,
    on_clear_filters: Callback<MouseEvent>,
) -> Html {
    let custom_owner_selected = !filter.owner.is_empty()
        && !owners
            .iter()
            .any(|owner| owner.eq_ignore_ascii_case(&filter.owner));

    html! {
        <section class="filter-bar" aria-label="Repository Filters">
            <div class="filter-controls">
                <div class="filter-field filter-search">
                    <label for="repo-search-input">{ "Search" }</label>
                    <input
                        id="repo-search-input"
                        type="search"
                        placeholder="Filter by owner, repo name, or canonical path..."
                        value={filter.query.clone()}
                        oninput={on_query_input}
                    />
                </div>

                <div class="filter-field">
                    <label for="repo-scope-select">{ "Scope" }</label>
                    <select
                        id="repo-scope-select"
                        value={filter.scope.as_str()}
                        onchange={on_scope_change}
                    >
                        <option value={ScopeFilter::All.as_str()} selected={filter.scope == ScopeFilter::All}>
                            { ScopeFilter::All.label() }
                        </option>
                        <option value={ScopeFilter::Users.as_str()} selected={filter.scope == ScopeFilter::Users}>
                            { ScopeFilter::Users.label() }
                        </option>
                        <option value={ScopeFilter::Teams.as_str()} selected={filter.scope == ScopeFilter::Teams}>
                            { ScopeFilter::Teams.label() }
                        </option>
                    </select>
                </div>

                <div class="filter-field">
                    <label for="repo-owner-select">{ "Owner / Team" }</label>
                    <select
                        id="repo-owner-select"
                        value={filter.owner.clone()}
                        onchange={on_owner_change}
                    >
                        <option value="" selected={filter.owner.is_empty()}>
                            { "All Owners / Teams" }
                        </option>
                        if custom_owner_selected {
                            <option value={filter.owner.clone()} selected=true>
                                { filter.owner.clone() }
                            </option>
                        }
                        { for owners.iter().map(|owner| {
                            let selected = filter.owner.eq_ignore_ascii_case(owner);
                            html! {
                                <option value={owner.clone()} selected={selected}>
                                    { owner.clone() }
                                </option>
                            }
                        }) }
                    </select>
                </div>

                <div class="filter-field">
                    <label for="repo-visibility-select">{ "Visibility" }</label>
                    <select
                        id="repo-visibility-select"
                        value={filter.visibility.as_str()}
                        onchange={on_visibility_change}
                    >
                        <option value={VisibilityFilter::All.as_str()} selected={filter.visibility == VisibilityFilter::All}>
                            { VisibilityFilter::All.label() }
                        </option>
                        <option value={VisibilityFilter::Public.as_str()} selected={filter.visibility == VisibilityFilter::Public}>
                            { VisibilityFilter::Public.label() }
                        </option>
                        <option value={VisibilityFilter::Private.as_str()} selected={filter.visibility == VisibilityFilter::Private}>
                            { VisibilityFilter::Private.label() }
                        </option>
                    </select>
                </div>
            </div>

            <div class="filter-summary-row">
                <span class="repo-count-summary">
                    { format!("Showing {matched_count} of {total_count} repositories") }
                </span>
                if !filter.is_empty() {
                    <button
                        type="button"
                        class="btn btn-link"
                        onclick={on_clear_filters}
                    >
                        { "Clear Filters" }
                    </button>
                }
            </div>
        </section>
    }
}

#[allow(clippy::too_many_arguments)]
fn render_repo_card(
    repo: &RepositoryItem,
    ssh_host: &str,
    https_host: &str,
    auth_user: Option<&str>,
    clone_protocol: CloneProtocol,
    on_protocol_change: &Callback<CloneProtocol>,
    copied_target: Option<&CopyTarget>,
    trigger_copy: &Callback<(String, CopyTarget)>,
    on_navigate: &Callback<AppRoute>,
) -> Html {
    let scope_badge = repo.scope_badge();
    let vis_badge = repo.visibility_badge();
    let canonical = repo.canonical_path.clone();
    let repo_href = repo.root_route();
    let repo_coords = repo.coordinates();
    let is_public = repo.is_public();
    let use_https = is_public && clone_protocol == CloneProtocol::Https;

    let (active_cmd, active_url, cmd_target, url_target, cmd_default_label, url_default_label) =
        if use_https {
            let cmd = if !repo.https_clone_command.is_empty() && https_host.trim().is_empty() {
                repo.https_clone_command.clone()
            } else {
                repo.https_clone_command_for(https_host)
            };
            let url = if !repo.https_url.is_empty() && https_host.trim().is_empty() {
                repo.https_url.clone()
            } else {
                repo.https_url_for(https_host)
            };
            (
                cmd,
                url,
                CopyTarget::HttpsCloneCommand(canonical.clone()),
                CopyTarget::HttpsUrl(canonical.clone()),
                "Copy HTTPS clone",
                "Copy HTTPS URL",
            )
        } else {
            (
                repo.clone_command_for(ssh_host, auth_user),
                repo.ssh_url_for(ssh_host, auth_user),
                CopyTarget::CloneCommand(canonical.clone()),
                CopyTarget::SshUrl(canonical.clone()),
                "Copy git clone",
                "Copy SSH URL",
            )
        };

    let is_cmd_copied = copied_target == Some(&cmd_target);
    let is_url_copied = copied_target == Some(&url_target);

    let cmd_btn_label = copy_button_label(copied_target, &cmd_target, cmd_default_label);
    let url_btn_label = copy_button_label(copied_target, &url_target, url_default_label);

    let on_copy_cmd = {
        let trigger_copy = trigger_copy.clone();
        let active_cmd = active_cmd.clone();
        Callback::from(move |_: MouseEvent| {
            trigger_copy.emit((active_cmd.clone(), cmd_target.clone()));
        })
    };

    let on_copy_url = {
        let trigger_copy = trigger_copy.clone();
        let active_url = active_url.clone();
        Callback::from(move |_: MouseEvent| {
            trigger_copy.emit((active_url.clone(), url_target.clone()));
        })
    };

    let on_open_repo = {
        let on_navigate = on_navigate.clone();
        let repo_coords = repo_coords.clone();
        Callback::from(move |e: MouseEvent| {
            if !e.ctrl_key() && !e.meta_key() && !e.shift_key() && !e.alt_key() && e.button() == 0 {
                if let Some(ref coords) = repo_coords {
                    e.prevent_default();
                    on_navigate.emit(AppRoute::RepoRoot {
                        repo: coords.clone(),
                    });
                }
            }
        })
    };

    html! {
        <article class="repo-card" key={canonical.clone()}>
            <div class="repo-card-main">
                <div class="repo-title-row">
                    <a
                        href={repo_href.clone()}
                        class="repo-name repo-name-link"
                        onclick={on_open_repo.clone()}
                    >
                        { format!("{}.git", repo.name) }
                    </a>
                    <span class={classes!("badge", format!("badge-scope-{scope_badge}"))}>
                        { scope_badge }
                    </span>
                    <span class={classes!("badge", format!("badge-vis-{vis_badge}"))}>
                        { vis_badge }
                    </span>
                </div>
                <div class="repo-canonical-path">
                    <a
                        href={repo_href}
                        class="repo-canonical-link"
                        onclick={on_open_repo}
                    >
                        <code>{ &canonical }</code>
                    </a>
                </div>
                <div class="repo-command-preview">
                    <code>{ &active_cmd }</code>
                </div>
            </div>

            <div class="repo-card-actions">
                if is_public {
                    { render_clone_protocol_toggle(clone_protocol, on_protocol_change) }
                }
                <button
                    type="button"
                    class={classes!("btn", "btn-copy", is_cmd_copied.then_some("btn-copied"))}
                    onclick={on_copy_cmd}
                    title={active_cmd}
                >
                    { cmd_btn_label }
                </button>
                <button
                    type="button"
                    class={classes!("btn", "btn-copy", is_url_copied.then_some("btn-copied"))}
                    onclick={on_copy_url}
                    title={active_url}
                >
                    { url_btn_label }
                </button>
            </div>
        </article>
    }
}

#[allow(clippy::too_many_arguments)]
fn render_repo_group(
    group: &RepositoryGroup,
    ssh_host: &str,
    https_host: &str,
    auth_user: Option<&str>,
    clone_protocol: CloneProtocol,
    on_protocol_change: &Callback<CloneProtocol>,
    copied_target: Option<&CopyTarget>,
    trigger_copy: &Callback<(String, CopyTarget)>,
    on_navigate: &Callback<AppRoute>,
) -> Html {
    let group_badge = group.scope_badge();
    let group_count = group.repositories.len();

    html! {
        <div class="repo-group" key={group.group_path.clone()}>
            <div class="repo-group-header">
                <div class="repo-group-title">
                    <span class={classes!("badge", format!("badge-scope-{group_badge}"))}>
                        { group_badge }
                    </span>
                    <h2 class="group-path">{ &group.group_path }</h2>
                </div>
                <span class="group-count">
                    { if group_count == 1 {
                        "1 repository".to_owned()
                    } else {
                        format!("{group_count} repositories")
                    } }
                </span>
            </div>

            <div class="repo-list">
                { for group.repositories.iter().map(|repo| {
                    render_repo_card(
                        repo,
                        ssh_host,
                        https_host,
                        auth_user,
                        clone_protocol,
                        on_protocol_change,
                        copied_target,
                        trigger_copy,
                        on_navigate,
                    )
                }) }
            </div>
        </div>
    }
}

#[allow(clippy::too_many_arguments)]
fn render_sign_in_modal(
    username: &str,
    ttl_secs: u64,
    signature: &str,
    challenge_res: &Result<SignInChallenge, String>,
    modal_error: Option<&str>,
    verifying: bool,
    copied_target: Option<&CopyTarget>,
    trigger_copy: &Callback<(String, CopyTarget)>,
    on_username_input: Callback<InputEvent>,
    on_ttl_change: Callback<Event>,
    on_signature_input: Callback<InputEvent>,
    on_submit: Callback<SubmitEvent>,
    on_close: Callback<MouseEvent>,
) -> Html {
    html! {
        <div class="modal-backdrop" role="dialog" aria-modal="true" aria-labelledby="ssh-modal-title">
            <div class="modal-panel">
                <div class="modal-header">
                    <h2 id="ssh-modal-title">{ "Sign In with SSH Key (Stateless sshsig)" }</h2>
                    <button
                        type="button"
                        class="btn btn-icon"
                        onclick={on_close.clone()}
                        aria-label="Close modal"
                    >
                        { "×" }
                    </button>
                </div>

                <form class="modal-body" onsubmit={on_submit}>
                    <p class="modal-intro">
                        { "Sign a timestamped challenge locally with your SSH key using " }
                        <code>{ "ssh-keygen -Y sign" }</code>
                        { " to unlock private user and team repositories." }
                    </p>

                    <div class="modal-grid">
                        <div class="filter-field">
                            <label for="ssh-username-input">{ "1. Linux / Git Username" }</label>
                            <input
                                id="ssh-username-input"
                                type="text"
                                placeholder="e.g. alice"
                                value={username.to_owned()}
                                oninput={on_username_input}
                                autocomplete="username"
                                required=true
                            />
                        </div>

                        <div class="filter-field">
                            <label for="ssh-ttl-select">{ "Token Lifetime (TTL)" }</label>
                            <select
                                id="ssh-ttl-select"
                                value={ttl_secs.to_string()}
                                onchange={on_ttl_change}
                            >
                                { for TTL_OPTIONS.iter().map(|opt| {
                                    let selected = ttl_secs == opt.seconds;
                                    html! {
                                        <option value={opt.seconds.to_string()} selected={selected}>
                                            { opt.label }
                                        </option>
                                    }
                                }) }
                            </select>
                        </div>
                    </div>

                    <div class="filter-field">
                        <div class="label-with-action">
                            <label>{ "2. Run in your terminal to sign the challenge" }</label>
                            if let Ok(challenge) = challenge_res {
                                <button
                                    type="button"
                                    class={classes!(
                                        "btn",
                                        "btn-copy",
                                        "btn-sm",
                                        (copied_target == Some(&CopyTarget::SignCommand)).then_some("btn-copied")
                                    )}
                                    onclick={{
                                        let cmd = challenge.sign_command.clone();
                                        let trigger_copy = trigger_copy.clone();
                                        Callback::from(move |_: MouseEvent| {
                                            trigger_copy.emit((cmd.clone(), CopyTarget::SignCommand));
                                        })
                                    }}
                                >
                                    { copy_button_label(
                                        copied_target,
                                        &CopyTarget::SignCommand,
                                        "Copy Command",
                                    ) }
                                </button>
                            }
                        </div>

                        <pre class="command-box">
                            <code>
                                { match challenge_res {
                                    Ok(challenge) => challenge.sign_command.clone(),
                                    Err(_) => "Enter a valid username ([a-zA-Z0-9_-]+) above to generate your ssh-keygen command.".to_owned(),
                                } }
                            </code>
                        </pre>
                    </div>

                    <div class="filter-field">
                        <label for="ssh-signature-textarea">
                            { "3. Paste SSH Signature Output" }
                        </label>
                        <textarea
                            id="ssh-signature-textarea"
                            rows="6"
                            placeholder="-----BEGIN SSH SIGNATURE-----\n...\n-----END SSH SIGNATURE-----"
                            value={signature.to_owned()}
                            oninput={on_signature_input}
                            required=true
                        />
                    </div>

                    if let Some(err) = modal_error {
                        <div class="alert alert-error" role="alert">
                            <span>{ err }</span>
                        </div>
                    }

                    <div class="modal-footer">
                        <button
                            type="button"
                            class="btn btn-secondary"
                            onclick={on_close}
                            disabled={verifying}
                        >
                            { "Cancel" }
                        </button>
                        <button
                            type="submit"
                            class="btn btn-primary"
                            disabled={verifying || challenge_res.is_err() || signature.trim().is_empty()}
                        >
                            { if verifying { "Verifying..." } else { "Verify & Sign In" } }
                        </button>
                    </div>
                </form>
            </div>
        </div>
    }
}

#[function_component(App)]
pub fn app() -> Html {
    let route = use_state(current_browser_route);
    let auth_status = use_state(AuthStatus::default);
    let repositories = use_state(Vec::<RepositoryItem>::new);
    let filter = use_state(RepoFilter::default);
    let clone_protocol = use_state(CloneProtocol::default);
    let loading = use_state(|| true);
    let load_error = use_state(|| Option::<String>::None);
    let refresh_seq = use_state(|| 0u32);

    // Repository browser state
    let repo_overview = use_state(|| Option::<RepositoryOverviewModel>::None);
    let tree_view = use_state(|| Option::<TreeViewModel>::None);
    let readme_blob = use_state(|| Option::<BlobViewModel>::None);
    let blob_view = use_state(|| Option::<BlobViewModel>::None);
    let blob_view_mode = use_state(BlobViewMode::default);
    let commit_list = use_state(|| Option::<CommitListModel>::None);
    let commit_detail = use_state(|| Option::<CommitDetailModel>::None);

    let copied_target = use_state(|| Option::<CopyTarget>::None);

    // SSH Sign-In Modal state
    let modal_open = use_state(|| false);
    let modal_username = use_state(String::new);
    let modal_ttl_secs = use_state(|| DEFAULT_TTL_SECS);
    let modal_base_unix = use_state(current_unix_secs);
    let modal_signature = use_state(String::new);
    let modal_error = use_state(|| Option::<String>::None);
    let modal_verifying = use_state(|| false);

    // Register browser `popstate` listener for Back/Forward navigation.
    {
        let route = route.clone();
        let blob_view_mode = blob_view_mode.clone();
        use_effect_with((), move |()| {
            let maybe_listener = web_sys::window().map(|window| {
                let cb = Closure::<dyn FnMut(PopStateEvent)>::new(move |_: PopStateEvent| {
                    blob_view_mode.set(BlobViewMode::Rendered);
                    route.set(current_browser_route());
                });
                let _ = window
                    .add_event_listener_with_callback("popstate", cb.as_ref().unchecked_ref());
                (window, cb)
            });

            move || {
                if let Some((window, cb)) = maybe_listener {
                    let _ = window.remove_event_listener_with_callback(
                        "popstate",
                        cb.as_ref().unchecked_ref(),
                    );
                }
            }
        });
    }

    // Fetch auth status and active route data on mount and whenever `(route, refresh_seq)` changes.
    {
        let active_route = (*route).clone();
        let seq = *refresh_seq;
        let auth_status = auth_status.clone();
        let repositories = repositories.clone();
        let repo_overview = repo_overview.clone();
        let tree_view = tree_view.clone();
        let readme_blob = readme_blob.clone();
        let blob_view = blob_view.clone();
        let commit_list = commit_list.clone();
        let commit_detail = commit_detail.clone();
        let loading = loading.clone();
        let load_error = load_error.clone();

        use_effect_with((active_route, seq), move |(target_route, _)| {
            let cancelled = Rc::new(Cell::new(false));
            let cancelled_for_task = Rc::clone(&cancelled);
            let target_route = target_route.clone();
            let mut current_auth = (*auth_status).clone();

            let should_clear_overview = match (target_route.repo(), (*repo_overview).as_ref()) {
                (Some(target_repo), Some(ov)) => {
                    ov.repository.coordinates().as_ref() != Some(target_repo)
                }
                (None, Some(_)) => true,
                _ => false,
            };
            if should_clear_overview {
                repo_overview.set(None);
                tree_view.set(None);
                readme_blob.set(None);
                blob_view.set(None);
                commit_list.set(None);
                commit_detail.set(None);
            }

            loading.set(true);
            load_error.set(None);

            spawn_local(async move {
                let stored_token = load_stored_token();
                let effective_token = match fetch_auth_status(stored_token.as_deref()).await {
                    Ok(status) => {
                        if cancelled_for_task.get() {
                            return;
                        }
                        let is_authed = status.authenticated;
                        current_auth = status.clone();
                        auth_status.set(status);
                        if !is_authed && stored_token.is_some() {
                            clear_stored_token();
                            None
                        } else {
                            stored_token
                        }
                    }
                    Err(err) => {
                        if cancelled_for_task.get() {
                            return;
                        }
                        load_error.set(Some(err));
                        stored_token
                    }
                };

                let token_ref = effective_token.as_deref();

                match &target_route {
                    AppRoute::Index => {
                        match fetch_repositories(token_ref).await {
                            Ok(snapshot) => {
                                if cancelled_for_task.get() {
                                    return;
                                }
                                let mut auth_changed = false;
                                if snapshot.ssh_host != DEFAULT_SSH_HOST
                                    && current_auth.ssh_host != snapshot.ssh_host
                                {
                                    current_auth.ssh_host = snapshot.ssh_host.clone();
                                    auth_changed = true;
                                }
                                if snapshot.https_host != DEFAULT_HTTPS_HOST
                                    && current_auth.https_host != snapshot.https_host
                                {
                                    current_auth.https_host = snapshot.https_host.clone();
                                    auth_changed = true;
                                }
                                if auth_changed {
                                    auth_status.set(current_auth);
                                }
                                repositories.set(snapshot.repositories);
                            }
                            Err(err) => {
                                if cancelled_for_task.get() {
                                    return;
                                }
                                load_error.set(Some(err));
                            }
                        }
                    }
                    AppRoute::RepoRoot { repo } => {
                        tree_view.set(None);
                        readme_blob.set(None);
                        match fetch_repository_overview(
                            &repo.scope,
                            &repo.owner,
                            &repo.visibility,
                            &repo.name,
                            None,
                            token_ref,
                        )
                        .await
                        {
                            Ok(ov) => {
                                if cancelled_for_task.get() {
                                    return;
                                }
                                let rev = ov.effective_revision().to_owned();
                                let maybe_readme = find_readme_entry(&ov.entries).cloned();
                                repo_overview.set(Some(ov));

                                if let Some(readme_entry) = maybe_readme {
                                    if let Ok(blob) = fetch_blob_view(
                                        &repo.scope,
                                        &repo.owner,
                                        &repo.visibility,
                                        &repo.name,
                                        &rev,
                                        &readme_entry.path,
                                        token_ref,
                                    )
                                    .await
                                    {
                                        if !cancelled_for_task.get() {
                                            readme_blob.set(Some(blob));
                                        }
                                    }
                                }
                            }
                            Err(err) => {
                                if !cancelled_for_task.get() {
                                    load_error.set(Some(err));
                                }
                            }
                        }
                    }
                    AppRoute::Tree {
                        repo,
                        revision,
                        path,
                    } => {
                        tree_view.set(None);
                        readme_blob.set(None);
                        if let Ok(ov) = fetch_repository_overview(
                            &repo.scope,
                            &repo.owner,
                            &repo.visibility,
                            &repo.name,
                            Some(revision),
                            token_ref,
                        )
                        .await
                        {
                            if cancelled_for_task.get() {
                                return;
                            }
                            repo_overview.set(Some(ov));
                        }

                        match fetch_tree_view(
                            &repo.scope,
                            &repo.owner,
                            &repo.visibility,
                            &repo.name,
                            revision,
                            path,
                            token_ref,
                        )
                        .await
                        {
                            Ok(tv) => {
                                if cancelled_for_task.get() {
                                    return;
                                }
                                let rev = if tv.revision.is_empty() {
                                    revision.clone()
                                } else {
                                    tv.revision.clone()
                                };
                                let maybe_readme = find_readme_entry(&tv.entries).cloned();
                                tree_view.set(Some(tv));

                                if let Some(readme_entry) = maybe_readme {
                                    if let Ok(blob) = fetch_blob_view(
                                        &repo.scope,
                                        &repo.owner,
                                        &repo.visibility,
                                        &repo.name,
                                        &rev,
                                        &readme_entry.path,
                                        token_ref,
                                    )
                                    .await
                                    {
                                        if !cancelled_for_task.get() {
                                            readme_blob.set(Some(blob));
                                        }
                                    }
                                }
                            }
                            Err(err) => {
                                if !cancelled_for_task.get() {
                                    load_error.set(Some(err));
                                }
                            }
                        }
                    }
                    AppRoute::Blob {
                        repo,
                        revision,
                        path,
                    } => {
                        blob_view.set(None);
                        if let Ok(ov) = fetch_repository_overview(
                            &repo.scope,
                            &repo.owner,
                            &repo.visibility,
                            &repo.name,
                            Some(revision),
                            token_ref,
                        )
                        .await
                        {
                            if cancelled_for_task.get() {
                                return;
                            }
                            repo_overview.set(Some(ov));
                        }

                        match fetch_blob_view(
                            &repo.scope,
                            &repo.owner,
                            &repo.visibility,
                            &repo.name,
                            revision,
                            path,
                            token_ref,
                        )
                        .await
                        {
                            Ok(bv) => {
                                if !cancelled_for_task.get() {
                                    blob_view.set(Some(bv));
                                }
                            }
                            Err(err) => {
                                if !cancelled_for_task.get() {
                                    load_error.set(Some(err));
                                }
                            }
                        }
                    }
                    AppRoute::Commits {
                        repo,
                        revision,
                        path,
                        offset,
                    } => {
                        commit_list.set(None);
                        if let Ok(ov) = fetch_repository_overview(
                            &repo.scope,
                            &repo.owner,
                            &repo.visibility,
                            &repo.name,
                            Some(revision),
                            token_ref,
                        )
                        .await
                        {
                            if cancelled_for_task.get() {
                                return;
                            }
                            repo_overview.set(Some(ov));
                        }

                        match fetch_commit_list(
                            &repo.scope,
                            &repo.owner,
                            &repo.visibility,
                            &repo.name,
                            revision,
                            path,
                            COMMITS_PAGE_SIZE,
                            *offset,
                            token_ref,
                        )
                        .await
                        {
                            Ok(cl) => {
                                if !cancelled_for_task.get() {
                                    commit_list.set(Some(cl));
                                }
                            }
                            Err(err) => {
                                if !cancelled_for_task.get() {
                                    load_error.set(Some(err));
                                }
                            }
                        }
                    }
                    AppRoute::CommitDetail { repo, revision } => {
                        commit_detail.set(None);
                        if let Ok(ov) = fetch_repository_overview(
                            &repo.scope,
                            &repo.owner,
                            &repo.visibility,
                            &repo.name,
                            None,
                            token_ref,
                        )
                        .await
                        {
                            if cancelled_for_task.get() {
                                return;
                            }
                            repo_overview.set(Some(ov));
                        }

                        match fetch_commit_detail(
                            &repo.scope,
                            &repo.owner,
                            &repo.visibility,
                            &repo.name,
                            revision,
                            token_ref,
                        )
                        .await
                        {
                            Ok(cd) => {
                                if !cancelled_for_task.get() {
                                    commit_detail.set(Some(cd));
                                }
                            }
                            Err(err) => {
                                if !cancelled_for_task.get() {
                                    load_error.set(Some(err));
                                }
                            }
                        }
                    }
                }

                if !cancelled_for_task.get() {
                    loading.set(false);
                }
            });

            move || cancelled.set(true)
        });
    }

    let on_navigate = {
        let route = route.clone();
        let blob_view_mode = blob_view_mode.clone();
        Callback::from(move |next_route: AppRoute| {
            push_browser_route(&next_route);
            blob_view_mode.set(BlobViewMode::Rendered);
            route.set(next_route);
        })
    };

    let on_markdown_navigate = {
        let on_navigate = on_navigate.clone();
        Callback::from(move |raw_href: String| {
            if let Some(parsed) = parse_app_route(&raw_href) {
                on_navigate.emit(parsed);
            }
        })
    };

    let on_revision_change = {
        let current_route = (*route).clone();
        let on_navigate = on_navigate.clone();
        Callback::from(move |e: Event| {
            if let Some(select) = e
                .target()
                .and_then(|t| t.dyn_into::<HtmlSelectElement>().ok())
            {
                let next_rev = select.value();
                if !next_rev.trim().is_empty() {
                    on_navigate.emit(current_route.with_revision(&next_rev));
                }
            }
        })
    };

    let on_blob_mode_change = {
        let blob_view_mode = blob_view_mode.clone();
        Callback::from(move |mode: BlobViewMode| {
            blob_view_mode.set(mode);
        })
    };

    let on_protocol_change = {
        let clone_protocol = clone_protocol.clone();
        Callback::from(move |protocol: CloneProtocol| {
            clone_protocol.set(protocol);
        })
    };

    let trigger_copy = {
        let copied_target = copied_target.clone();
        Callback::from(move |(text, target): (String, CopyTarget)| {
            copy_text_to_clipboard(text);
            copied_target.set(Some(target.clone()));
            let copied_target = copied_target.clone();
            Timeout::new(2_000, move || {
                if *copied_target == Some(target) {
                    copied_target.set(None);
                }
            })
            .forget();
        })
    };

    let on_refresh = {
        let refresh_seq = refresh_seq.clone();
        Callback::from(move |_: MouseEvent| {
            refresh_seq.set(refresh_seq.wrapping_add(1));
        })
    };

    let on_open_sign_in = {
        let modal_open = modal_open.clone();
        let modal_base_unix = modal_base_unix.clone();
        let modal_error = modal_error.clone();
        let modal_signature = modal_signature.clone();
        Callback::from(move |_: MouseEvent| {
            modal_base_unix.set(current_unix_secs());
            modal_error.set(None);
            modal_signature.set(String::new());
            modal_open.set(true);
        })
    };

    let on_close_sign_in = {
        let modal_open = modal_open.clone();
        let modal_error = modal_error.clone();
        Callback::from(move |_: MouseEvent| {
            modal_open.set(false);
            modal_error.set(None);
        })
    };

    let on_sign_out = {
        let auth_status = auth_status.clone();
        let refresh_seq = refresh_seq.clone();
        Callback::from(move |_: MouseEvent| {
            clear_stored_token();
            let current_ssh = auth_status.ssh_host.clone();
            let current_https = auth_status.https_host.clone();
            auth_status.set(AuthStatus::anonymous(&current_ssh).with_https_host(&current_https));
            refresh_seq.set(refresh_seq.wrapping_add(1));
        })
    };

    let on_query_input = {
        let filter = filter.clone();
        Callback::from(move |e: InputEvent| {
            if let Some(input) = e
                .target()
                .and_then(|t| t.dyn_into::<HtmlInputElement>().ok())
            {
                let mut next = (*filter).clone();
                next.query = input.value();
                filter.set(next);
            }
        })
    };

    let on_scope_change = {
        let filter = filter.clone();
        let repositories = repositories.clone();
        Callback::from(move |e: Event| {
            if let Some(select) = e
                .target()
                .and_then(|t| t.dyn_into::<HtmlSelectElement>().ok())
            {
                let mut next = (*filter).clone();
                next.scope = ScopeFilter::from_value(&select.value());
                if !next.owner.is_empty() {
                    let scope_owners = available_owners(&repositories, next.scope);
                    if !scope_owners
                        .iter()
                        .any(|o| o.eq_ignore_ascii_case(&next.owner))
                    {
                        next.owner.clear();
                    }
                }
                filter.set(next);
            }
        })
    };

    let on_owner_change = {
        let filter = filter.clone();
        Callback::from(move |e: Event| {
            if let Some(select) = e
                .target()
                .and_then(|t| t.dyn_into::<HtmlSelectElement>().ok())
            {
                let mut next = (*filter).clone();
                next.owner = select.value();
                filter.set(next);
            }
        })
    };

    let on_visibility_change = {
        let filter = filter.clone();
        Callback::from(move |e: Event| {
            if let Some(select) = e
                .target()
                .and_then(|t| t.dyn_into::<HtmlSelectElement>().ok())
            {
                let mut next = (*filter).clone();
                next.visibility = VisibilityFilter::from_value(&select.value());
                filter.set(next);
            }
        })
    };

    let on_clear_filters = {
        let filter = filter.clone();
        Callback::from(move |_: MouseEvent| {
            filter.set(RepoFilter::default());
        })
    };

    let on_modal_username_input = {
        let modal_username = modal_username.clone();
        let modal_base_unix = modal_base_unix.clone();
        let modal_error = modal_error.clone();
        Callback::from(move |e: InputEvent| {
            if let Some(input) = e
                .target()
                .and_then(|t| t.dyn_into::<HtmlInputElement>().ok())
            {
                modal_username.set(input.value());
                modal_base_unix.set(current_unix_secs());
                modal_error.set(None);
            }
        })
    };

    let on_modal_ttl_change = {
        let modal_ttl_secs = modal_ttl_secs.clone();
        let modal_base_unix = modal_base_unix.clone();
        let modal_error = modal_error.clone();
        Callback::from(move |e: Event| {
            if let Some(select) = e
                .target()
                .and_then(|t| t.dyn_into::<HtmlSelectElement>().ok())
            {
                if let Ok(parsed) = select.value().parse::<u64>() {
                    modal_ttl_secs.set(parsed);
                    modal_base_unix.set(current_unix_secs());
                    modal_error.set(None);
                }
            }
        })
    };

    let on_modal_signature_input = {
        let modal_signature = modal_signature.clone();
        let modal_error = modal_error.clone();
        Callback::from(move |e: InputEvent| {
            if let Some(textarea) = e
                .target()
                .and_then(|t| t.dyn_into::<HtmlTextAreaElement>().ok())
            {
                modal_signature.set(textarea.value());
                modal_error.set(None);
            }
        })
    };

    let challenge_res =
        build_sign_in_challenge(&modal_username, *modal_base_unix, *modal_ttl_secs);

    let on_verify_and_sign_in = {
        let challenge_res = challenge_res.clone();
        let modal_signature = modal_signature.clone();
        let modal_error = modal_error.clone();
        let modal_verifying = modal_verifying.clone();
        let modal_open = modal_open.clone();
        let auth_status = auth_status.clone();
        let refresh_seq = refresh_seq.clone();

        Callback::from(move |e: SubmitEvent| {
            e.prevent_default();
            if *modal_verifying {
                return;
            }

            let challenge = match &challenge_res {
                Ok(c) => c.clone(),
                Err(err) => {
                    modal_error.set(Some(err.clone()));
                    return;
                }
            };

            let now = current_unix_secs();
            let token = match build_bearer_token_from_signature(&challenge, &modal_signature, now) {
                Ok(t) => t,
                Err(err) => {
                    modal_error.set(Some(err));
                    return;
                }
            };

            modal_verifying.set(true);
            modal_error.set(None);

            let modal_error = modal_error.clone();
            let modal_verifying = modal_verifying.clone();
            let modal_open = modal_open.clone();
            let auth_status = auth_status.clone();
            let refresh_seq = refresh_seq.clone();

            spawn_local(async move {
                let result = fetch_auth_status(Some(&token)).await.and_then(|status| {
                    verify_auth_status_for_user(&status, &challenge.username).map(|()| status)
                });

                match result {
                    Ok(status) => {
                        save_stored_token(&token);
                        auth_status.set(status);
                        modal_verifying.set(false);
                        modal_open.set(false);
                        refresh_seq.set(refresh_seq.wrapping_add(1));
                    }
                    Err(err) => {
                        modal_error.set(Some(err));
                        modal_verifying.set(false);
                    }
                }
            });
        })
    };

    let active_ssh_host = auth_status.ssh_host.clone();
    let active_https_host = auth_status.https_host.clone();
    let active_user = auth_status.username.clone();

    let main_body = match &*route {
        AppRoute::Index => {
            let owners = available_owners(&repositories, filter.scope);
            let groups = filter_and_group_repositories(&repositories, &filter);
            let matched_count: usize = groups.iter().map(|g| g.repositories.len()).sum();
            let total_count = repositories.len();

            html! {
                <>
                    { render_filter_bar(
                        &filter,
                        &owners,
                        matched_count,
                        total_count,
                        on_query_input,
                        on_scope_change,
                        on_owner_change,
                        on_visibility_change,
                        on_clear_filters,
                    ) }

                    <section class="repo-index" aria-label="Repository Groups">
                        if *loading && repositories.is_empty() {
                            <div class="empty-state">
                                <p>{ "Loading repository index..." }</p>
                            </div>
                        } else if groups.is_empty() {
                            <div class="empty-state">
                                if repositories.is_empty() {
                                    <p>{ "No accessible repositories discovered on this server." }</p>
                                    if !auth_status.authenticated {
                                        <p class="empty-hint">
                                            { "Sign in with your SSH key to unlock private user and team repositories." }
                                        </p>
                                    }
                                } else {
                                    <p>{ "No repositories match your active filters." }</p>
                                }
                            </div>
                        } else {
                            { for groups.iter().map(|group| {
                                render_repo_group(
                                    group,
                                    &active_ssh_host,
                                    &active_https_host,
                                    active_user.as_deref(),
                                    *clone_protocol,
                                    &on_protocol_change,
                                    (*copied_target).as_ref(),
                                    &trigger_copy,
                                    &on_navigate,
                                )
                            }) }
                        }
                    </section>
                </>
            }
        }
        repo_route => {
            let Some(repo) = repo_route.repo() else {
                return html! {};
            };
            let overview_ref = (*repo_overview)
                .as_ref()
                .filter(|ov| ov.repository.coordinates().as_ref() == Some(repo));
            let effective_rev = repo_route
                .active_revision()
                .or_else(|| overview_ref.map(RepositoryOverviewModel::effective_revision))
                .unwrap_or(DEFAULT_REVISION);

            let fallback_item = RepositoryItem::new(
                &active_ssh_host,
                active_user.as_deref(),
                &repo.scope,
                &repo.owner,
                &repo.visibility,
                &repo.name,
            );
            let item_ref = overview_ref
                .map(|ov| &ov.repository)
                .unwrap_or(&fallback_item);
            let clone_cmd = if item_ref.is_public() && *clone_protocol == CloneProtocol::Https {
                item_ref.https_clone_command_for(&active_https_host)
            } else {
                item_ref.clone_command_for(&active_ssh_host, active_user.as_deref())
            };

            let sub_view = match repo_route {
                AppRoute::RepoRoot { .. } => {
                    if let Some(ov) = overview_ref {
                        render_tree_view(
                            repo,
                            ov.effective_revision(),
                            "",
                            &ov.entries,
                            ov.is_empty_unborn(),
                            &clone_cmd,
                            (*readme_blob).as_ref(),
                            &on_navigate,
                            on_markdown_navigate.clone(),
                        )
                    } else if *loading {
                        html! {
                            <div class="empty-state">
                                <p>{ "Loading repository..." }</p>
                            </div>
                        }
                    } else {
                        html! {}
                    }
                }
                AppRoute::Tree { revision, path, .. } => {
                    if let Some(tv) = (*tree_view).as_ref() {
                        let rev = if tv.revision.is_empty() {
                            revision.as_str()
                        } else {
                            tv.revision.as_str()
                        };
                        let is_unborn = overview_ref
                            .map(RepositoryOverviewModel::is_empty_unborn)
                            .unwrap_or(false);
                        render_tree_view(
                            repo,
                            rev,
                            path,
                            &tv.entries,
                            is_unborn,
                            &clone_cmd,
                            (*readme_blob).as_ref(),
                            &on_navigate,
                            on_markdown_navigate.clone(),
                        )
                    } else if path.is_empty() {
                        if let Some(ov) = overview_ref {
                            render_tree_view(
                                repo,
                                revision,
                                "",
                                &ov.entries,
                                ov.is_empty_unborn(),
                                &clone_cmd,
                                (*readme_blob).as_ref(),
                                &on_navigate,
                                on_markdown_navigate.clone(),
                            )
                        } else if *loading {
                            html! {
                                <div class="empty-state">
                                    <p>{ "Loading directory tree..." }</p>
                                </div>
                            }
                        } else {
                            html! {}
                        }
                    } else if *loading {
                        html! {
                            <div class="empty-state">
                                <p>{ "Loading directory tree..." }</p>
                            </div>
                        }
                    } else {
                        html! {}
                    }
                }
                AppRoute::Blob { .. } => {
                    if let Some(bv) = (*blob_view).as_ref() {
                        let entry_mode = (*tree_view)
                            .as_ref()
                            .and_then(|tv| tv.entries.iter().find(|e| e.path == bv.path))
                            .or_else(|| {
                                overview_ref
                                    .and_then(|ov| ov.entries.iter().find(|e| e.path == bv.path))
                            })
                            .map(|e| e.mode.as_str());
                        render_blob_view(
                            repo,
                            bv,
                            entry_mode,
                            *blob_view_mode,
                            on_blob_mode_change,
                            &on_navigate,
                            on_markdown_navigate,
                        )
                    } else if *loading {
                        html! {
                            <div class="empty-state">
                                <p>{ "Loading blob..." }</p>
                            </div>
                        }
                    } else {
                        html! {}
                    }
                }
                AppRoute::Commits {
                    revision,
                    path,
                    offset,
                    ..
                } => {
                    if let Some(cl) = (*commit_list).as_ref() {
                        render_commits_view(
                            repo,
                            revision,
                            path,
                            *offset,
                            COMMITS_PAGE_SIZE,
                            cl,
                            &on_navigate,
                        )
                    } else if *loading {
                        html! {
                            <div class="empty-state">
                                <p>{ "Loading commit log..." }</p>
                            </div>
                        }
                    } else {
                        html! {}
                    }
                }
                AppRoute::CommitDetail { .. } => {
                    if let Some(cd) = (*commit_detail).as_ref() {
                        render_commit_detail_view(repo, cd, &on_navigate)
                    } else if *loading {
                        html! {
                            <div class="empty-state">
                                <p>{ "Loading commit diff..." }</p>
                            </div>
                        }
                    } else {
                        html! {}
                    }
                }
                AppRoute::Index => html! {},
            };

            html! {
                <>
                    { render_repository_header(
                        repo,
                        overview_ref,
                        effective_rev,
                        repo_route.is_commits_tab(),
                        &active_ssh_host,
                        &active_https_host,
                        active_user.as_deref(),
                        *clone_protocol,
                        &on_protocol_change,
                        (*copied_target).as_ref(),
                        &trigger_copy,
                        &on_navigate,
                        on_revision_change,
                    ) }
                    { sub_view }
                </>
            }
        }
    };

    html! {
        <main class="ro-git-app">
            { render_header(
                &auth_status,
                *loading,
                &on_navigate,
                on_refresh.clone(),
                on_open_sign_in,
                on_sign_out,
            ) }

            if let Some(err) = (*load_error).clone() {
                <div class="alert alert-error" role="alert">
                    <span>{ err }</span>
                    <button type="button" class="btn btn-secondary" onclick={on_refresh}>
                        { "Retry" }
                    </button>
                </div>
            }

            { main_body }

            if *modal_open {
                { render_sign_in_modal(
                    &modal_username,
                    *modal_ttl_secs,
                    &modal_signature,
                    &challenge_res,
                    (*modal_error).as_deref(),
                    *modal_verifying,
                    (*copied_target).as_ref(),
                    &trigger_copy,
                    on_modal_username_input,
                    on_modal_ttl_change,
                    on_modal_signature_input,
                    on_verify_and_sign_in,
                    on_close_sign_in,
                ) }
            }
        </main>
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{group_repositories, render_vnode_to_html_string};

    #[test]
    fn renders_public_and_private_repo_cards_in_ssh_and_https_modes() {
        let noop_proto = Callback::from(|_: CloneProtocol| {});
        let noop_copy = Callback::from(|_: (String, CopyTarget)| {});
        let noop_nav = Callback::from(|_: AppRoute| {});

        let pub_repo = RepositoryItem::new(
            "git.example.com",
            Some("alice"),
            "users",
            "alice",
            "public",
            "dotfiles.git",
        );
        let priv_repo = RepositoryItem::new(
            "git.example.com",
            Some("alice"),
            "teams",
            "core",
            "private",
            "infra.git",
        );

        // Public repo in SSH mode
        let pub_ssh_html = render_vnode_to_html_string(&render_repo_card(
            &pub_repo,
            "git.example.com",
            "https://git.example.com",
            Some("alice"),
            CloneProtocol::Ssh,
            &noop_proto,
            None,
            &noop_copy,
            &noop_nav,
        ));
        assert!(pub_ssh_html.contains("dotfiles.git"));
        assert!(pub_ssh_html.contains("clone-protocol-toggle"));
        assert!(pub_ssh_html.contains("git clone ssh://alice@git.example.com/users/alice/public/dotfiles.git"));
        assert!(pub_ssh_html.contains("Copy git clone"));
        assert!(pub_ssh_html.contains("Copy SSH URL"));

        // Public repo in HTTPS mode
        let pub_https_target = CopyTarget::HttpsCloneCommand(pub_repo.canonical_path.clone());
        let pub_https_html = render_vnode_to_html_string(&render_repo_card(
            &pub_repo,
            "git.example.com",
            "https://git.example.com",
            Some("alice"),
            CloneProtocol::Https,
            &noop_proto,
            Some(&pub_https_target),
            &noop_copy,
            &noop_nav,
        ));
        assert!(pub_https_html.contains("clone-protocol-toggle"));
        assert!(pub_https_html.contains("git clone https://git.example.com/users/alice/public/dotfiles.git"));
        assert!(pub_https_html.contains("Copied!"));
        assert!(pub_https_html.contains("Copy HTTPS URL"));

        // Private repo in HTTPS mode still renders SSH only and omits protocol toggle
        let groups = group_repositories(&[priv_repo]);
        let group_html = render_vnode_to_html_string(&render_repo_group(
            &groups[0],
            "git.example.com",
            "https://git.example.com",
            Some("alice"),
            CloneProtocol::Https,
            &noop_proto,
            None,
            &noop_copy,
            &noop_nav,
        ));
        assert!(!group_html.contains("clone-protocol-toggle"));
        assert!(group_html.contains("git clone ssh://alice@git.example.com/teams/core/private/infra.git"));
        assert!(group_html.contains("Copy git clone"));
        assert!(group_html.contains("Copy SSH URL"));
    }
}
