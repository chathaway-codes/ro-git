use crate::{
    available_owners, build_bearer_token_from_signature, build_sign_in_challenge,
    copy_button_label, decode_auth_status_response, decode_repositories_response,
    filter_and_group_repositories, format_authorization_header, verify_auth_status_for_user,
    AuthStatus, CopyTarget, RepoFilter, RepositoryItem, ScopeFilter, VisibilityFilter,
    DEFAULT_SSH_HOST, DEFAULT_TTL_SECS, LOCAL_STORAGE_TOKEN_KEY, TTL_OPTIONS,
};
use gloo_timers::callback::Timeout;
use js_sys::{Date, Uint8Array};
use ro_git_proto::{API_AUTH_STATUS_PATH, API_REPOSITORIES_PATH};
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::{spawn_local, JsFuture};
use web_sys::{
    HtmlInputElement, HtmlSelectElement, HtmlTextAreaElement, Request, RequestInit, Response,
    Storage,
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

#[function_component(App)]
pub fn app() -> Html {
    let auth_status = use_state(AuthStatus::default);
    let repositories = use_state(Vec::<RepositoryItem>::new);
    let filter = use_state(RepoFilter::default);
    let loading = use_state(|| true);
    let load_error = use_state(|| Option::<String>::None);
    let refresh_seq = use_state(|| 0u32);

    let copied_target = use_state(|| Option::<CopyTarget>::None);

    // SSH Sign-In Modal state
    let modal_open = use_state(|| false);
    let modal_username = use_state(String::new);
    let modal_ttl_secs = use_state(|| DEFAULT_TTL_SECS);
    let modal_base_unix = use_state(current_unix_secs);
    let modal_signature = use_state(String::new);
    let modal_error = use_state(|| Option::<String>::None);
    let modal_verifying = use_state(|| false);

    // Fetch auth status and repository index on mount and whenever `refresh_seq` changes.
    {
        let auth_status = auth_status.clone();
        let repositories = repositories.clone();
        let loading = loading.clone();
        let load_error = load_error.clone();
        let seq = *refresh_seq;

        use_effect_with(seq, move |_| {
            loading.set(true);
            load_error.set(None);

            spawn_local(async move {
                let stored_token = load_stored_token();
                let auth_res =
                    fetch_protobuf_bytes(API_AUTH_STATUS_PATH, stored_token.as_deref()).await;
                let effective_token = match auth_res {
                    Ok(bytes) => match decode_auth_status_response(&bytes) {
                        Ok(status) => {
                            let is_authed = status.authenticated;
                            auth_status.set(status);
                            if !is_authed && stored_token.is_some() {
                                clear_stored_token();
                                None
                            } else {
                                stored_token
                            }
                        }
                        Err(err) => {
                            load_error.set(Some(err));
                            stored_token
                        }
                    },
                    Err(err) => {
                        load_error.set(Some(err));
                        stored_token
                    }
                };

                match fetch_protobuf_bytes(API_REPOSITORIES_PATH, effective_token.as_deref()).await
                {
                    Ok(bytes) => match decode_repositories_response(&bytes) {
                        Ok(snapshot) => {
                            if snapshot.ssh_host != DEFAULT_SSH_HOST {
                                let mut updated = (*auth_status).clone();
                                updated.ssh_host = snapshot.ssh_host.clone();
                                auth_status.set(updated);
                            }
                            repositories.set(snapshot.repositories);
                        }
                        Err(err) => load_error.set(Some(err)),
                    },
                    Err(err) => load_error.set(Some(err)),
                }

                loading.set(false);
            });

            || ()
        });
    }

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
            let current_host = auth_status.ssh_host.clone();
            auth_status.set(AuthStatus::anonymous(&current_host));
            refresh_seq.set(refresh_seq.wrapping_add(1));
        })
    };

    // Filter callbacks
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
        Callback::from(move |e: Event| {
            if let Some(select) = e
                .target()
                .and_then(|t| t.dyn_into::<HtmlSelectElement>().ok())
            {
                let mut next = (*filter).clone();
                next.scope = ScopeFilter::from_value(&select.value());
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

    // Modal input callbacks
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
                match fetch_protobuf_bytes(API_AUTH_STATUS_PATH, Some(&token)).await {
                    Ok(bytes) => match decode_auth_status_response(&bytes) {
                        Ok(status) => match verify_auth_status_for_user(&status, &challenge.username)
                        {
                            Ok(()) => {
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
                        },
                        Err(err) => {
                            modal_error.set(Some(err));
                            modal_verifying.set(false);
                        }
                    },
                    Err(err) => {
                        modal_error.set(Some(format!(
                            "Failed to verify token against {API_AUTH_STATUS_PATH}: {err}"
                        )));
                        modal_verifying.set(false);
                    }
                }
            });
        })
    };

    let owners = available_owners(&repositories, filter.scope);
    let groups = filter_and_group_repositories(&repositories, &filter);
    let matched_count: usize = groups.iter().map(|g| g.repositories.len()).sum();
    let total_count = repositories.len();
    let active_ssh_host = auth_status.ssh_host.clone();
    let active_user = auth_status.username.clone();

    html! {
        <main class="ro-git-app">
            <header class="app-header">
                <div class="brand-block">
                    <div class="brand-title-row">
                        <h1 class="brand-title">{ "ro-git" }</h1>
                        <span class="host-pill" title="Configured SSH host">
                            { format!("ssh://{active_ssh_host}") }
                        </span>
                    </div>
                    <p class="brand-subtitle">{ "Read-Only Git Repository Index" }</p>
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
                        onclick={on_refresh.clone()}
                        disabled={*loading}
                    >
                        { if *loading { "Refreshing..." } else { "Refresh" } }
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

            if let Some(err) = (*load_error).clone() {
                <div class="alert alert-error" role="alert">
                    <span>{ err }</span>
                    <button type="button" class="btn btn-secondary" onclick={on_refresh}>
                        { "Retry" }
                    </button>
                </div>
            }

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
                    { for groups.into_iter().map(|group| {
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
                                    { for group.repositories.into_iter().map(|repo| {
                                        let scope_badge = repo.scope_badge();
                                        let vis_badge = repo.visibility_badge();
                                        let canonical = repo.canonical_path.clone();
                                        let clone_cmd = repo.clone_command_for(&active_ssh_host, active_user.as_deref());
                                        let ssh_url = repo.ssh_url_for(&active_ssh_host, active_user.as_deref());

                                        let clone_target = CopyTarget::CloneCommand(canonical.clone());
                                        let ssh_target = CopyTarget::SshUrl(canonical.clone());

                                        let is_clone_copied = *copied_target == Some(clone_target.clone());
                                        let is_ssh_copied = *copied_target == Some(ssh_target.clone());

                                        let clone_btn_label = copy_button_label(
                                            (*copied_target).as_ref(),
                                            &clone_target,
                                            "Copy git clone",
                                        );
                                        let ssh_btn_label = copy_button_label(
                                            (*copied_target).as_ref(),
                                            &ssh_target,
                                            "Copy SSH URL",
                                        );

                                        let on_copy_clone = {
                                            let trigger_copy = trigger_copy.clone();
                                            let clone_cmd = clone_cmd.clone();
                                            let clone_target = clone_target.clone();
                                            Callback::from(move |_: MouseEvent| {
                                                trigger_copy.emit((clone_cmd.clone(), clone_target.clone()));
                                            })
                                        };

                                        let on_copy_ssh = {
                                            let trigger_copy = trigger_copy.clone();
                                            let ssh_url = ssh_url.clone();
                                            let ssh_target = ssh_target.clone();
                                            Callback::from(move |_: MouseEvent| {
                                                trigger_copy.emit((ssh_url.clone(), ssh_target.clone()));
                                            })
                                        };

                                        html! {
                                            <article class="repo-card" key={canonical.clone()}>
                                                <div class="repo-card-main">
                                                    <div class="repo-title-row">
                                                        <span class="repo-name">{ format!("{}.git", repo.name) }</span>
                                                        <span class={classes!("badge", format!("badge-scope-{scope_badge}"))}>
                                                            { scope_badge }
                                                        </span>
                                                        <span class={classes!("badge", format!("badge-vis-{vis_badge}"))}>
                                                            { vis_badge }
                                                        </span>
                                                    </div>
                                                    <div class="repo-canonical-path">
                                                        <code>{ &canonical }</code>
                                                    </div>
                                                    <div class="repo-command-preview">
                                                        <code>{ &clone_cmd }</code>
                                                    </div>
                                                </div>

                                                <div class="repo-card-actions">
                                                    <button
                                                        type="button"
                                                        class={classes!("btn", "btn-copy", is_clone_copied.then_some("btn-copied"))}
                                                        onclick={on_copy_clone}
                                                        title={clone_cmd}
                                                    >
                                                        { clone_btn_label }
                                                    </button>
                                                    <button
                                                        type="button"
                                                        class={classes!("btn", "btn-copy", is_ssh_copied.then_some("btn-copied"))}
                                                        onclick={on_copy_ssh}
                                                        title={ssh_url}
                                                    >
                                                        { ssh_btn_label }
                                                    </button>
                                                </div>
                                            </article>
                                        }
                                    }) }
                                </div>
                            </div>
                        }
                    }) }
                }
            </section>

            if *modal_open {
                <div class="modal-backdrop" role="dialog" aria-modal="true" aria-labelledby="ssh-modal-title">
                    <div class="modal-panel">
                        <div class="modal-header">
                            <h2 id="ssh-modal-title">{ "Sign In with SSH Key (Stateless sshsig)" }</h2>
                            <button
                                type="button"
                                class="btn btn-icon"
                                onclick={on_close_sign_in.clone()}
                                aria-label="Close modal"
                            >
                                { "×" }
                            </button>
                        </div>

                        <form class="modal-body" onsubmit={on_verify_and_sign_in}>
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
                                        value={(*modal_username).clone()}
                                        oninput={on_modal_username_input}
                                        autocomplete="username"
                                        required=true
                                    />
                                </div>

                                <div class="filter-field">
                                    <label for="ssh-ttl-select">{ "Token Lifetime (TTL)" }</label>
                                    <select
                                        id="ssh-ttl-select"
                                        value={modal_ttl_secs.to_string()}
                                        onchange={on_modal_ttl_change}
                                    >
                                        { for TTL_OPTIONS.iter().map(|opt| {
                                            let selected = *modal_ttl_secs == opt.seconds;
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
                                    if let Ok(challenge) = &challenge_res {
                                        <button
                                            type="button"
                                            class={classes!(
                                                "btn",
                                                "btn-copy",
                                                "btn-sm",
                                                (*copied_target == Some(CopyTarget::SignCommand)).then_some("btn-copied")
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
                                                (*copied_target).as_ref(),
                                                &CopyTarget::SignCommand,
                                                "Copy Command",
                                            ) }
                                        </button>
                                    }
                                </div>

                                <pre class="command-box">
                                    <code>
                                        { match &challenge_res {
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
                                    value={(*modal_signature).clone()}
                                    oninput={on_modal_signature_input}
                                    required=true
                                />
                            </div>

                            if let Some(err) = (*modal_error).clone() {
                                <div class="alert alert-error" role="alert">
                                    <span>{ err }</span>
                                </div>
                            }

                            <div class="modal-footer">
                                <button
                                    type="button"
                                    class="btn btn-secondary"
                                    onclick={on_close_sign_in}
                                    disabled={*modal_verifying}
                                >
                                    { "Cancel" }
                                </button>
                                <button
                                    type="submit"
                                    class="btn btn-primary"
                                    disabled={*modal_verifying || challenge_res.is_err() || modal_signature.trim().is_empty()}
                                >
                                    { if *modal_verifying { "Verifying..." } else { "Verify & Sign In" } }
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            }
        </main>
    }
}
