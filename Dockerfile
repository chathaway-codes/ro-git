FROM archlinux:latest AS workspace

# Step 1: Initialize keyring, update system packages, and install dependencies
RUN pacman-key --init && \
    pacman-key --populate archlinux && \
    pacman -Sy --noconfirm archlinux-keyring && \
    pacman -Syu --noconfirm --overwrite '*' \
        base-devel \
        git \
        openssh \
        python \
        curl \
        protobuf \
        rustup \
        pkgconf \
        openssl \
        trunk \
        wasm-bindgen \
        binaryen && \
    pacman -Scc --noconfirm

# Step 2: Install Rust toolchain, WASM target, and roto codegen plugins
ENV RUSTUP_HOME=/opt/rustup \
    CARGO_HOME=/opt/cargo \
    PATH=/opt/cargo/bin:$PATH \
    PROTOC=/usr/bin/protoc \
    PROTOC_INCLUDE=/usr/include

RUN mkdir -p /opt/cargo /opt/rustup && \
    rustup default stable && \
    rustup component add rustfmt clippy && \
    rustup target add wasm32-unknown-unknown && \
    cargo install --git https://github.com/chathaway-codes/roto \
        cargo-roto \
        protoc-gen-roto \
        protoc-gen-roto-grpc && \
    chmod -R a+rwX /opt/rustup /opt/cargo

# Step 3: Install Antigravity CLI (agy)
ARG AGY_VERSION="1.2.16-5594158052802560"
RUN curl -fSL "https://storage.googleapis.com/antigravity-public/antigravity-cli/${AGY_VERSION}/linux-x64/cli_linux_x64.tar.gz" | \
    tar -xz -C /tmp && \
    install -Dm755 /tmp/antigravity /usr/bin/agy && \
    rm -f /tmp/antigravity

# Step 4: Create non-root developer user matching default host UID/GID (1000)
ARG USERNAME=developer
ARG USER_UID=1000
ARG USER_GID=1000

RUN groupadd --gid ${USER_GID} ${USERNAME} && \
    useradd --uid ${USER_UID} --gid ${USER_GID} -m -s /bin/bash ${USERNAME} && \
    mkdir -p /home/${USERNAME}/.cargo && \
    mkdir -p /home/${USERNAME}/.gemini/antigravity-cli && \
    mkdir -p /home/${USERNAME}/.gemini/config/projects && \
    echo '{"autoExecutionPolicy": "always-proceed", "trustedWorkspaces": ["/workspace", "/tmp", "/home/developer"]}' > /home/${USERNAME}/.gemini/antigravity-cli/settings.json && \
    echo '{"userSettings": {"cliRemoteControlHostname": "ro-git-sandbox", "remoteControlHostname": "agy-ro-git", "autoExecutionPolicy": "always-proceed", "globalPermissionGrants": {"allow": ["command(*)", "read_url(*)", "mcp(*)"]}}}' > /home/${USERNAME}/.gemini/config/config.json && \
    chown -R ${USERNAME}:${USERNAME} /home/${USERNAME}

WORKDIR /workspace
RUN chown -R ${USERNAME}:${USERNAME} /workspace

USER ${USERNAME}

RUN git config --global user.name "charles" && \
    git config --global user.email "charles@tipsy.codes"

CMD ["/bin/bash"]

# ---------------------------------------------------------------------------
# Stage 2: Build release server binary and Yew WASM frontend assets
# ---------------------------------------------------------------------------
FROM workspace AS builder

USER root
WORKDIR /build

COPY Cargo.toml Cargo.lock ./
COPY proto ./proto
COPY crates ./crates

RUN cargo build --release --locked -p ro-git-server && \
    trunk build --release --config crates/ro-git-ui/Trunk.toml --dist /build/dist

# ---------------------------------------------------------------------------
# Stage 3: Minimal production runtime (sshd + git-auto-shell + ro-git-server)
# ---------------------------------------------------------------------------
FROM archlinux:latest AS production

RUN pacman-key --init && \
    pacman-key --populate archlinux && \
    pacman -Sy --noconfirm archlinux-keyring && \
    pacman -Syu --noconfirm --overwrite '*' \
        git \
        openssh \
        python \
        openssl \
        ca-certificates && \
    pacman -Scc --noconfirm && \
    install -dm0755 -o root -g root /users /teams /run/sshd /app/dist

COPY --from=builder --chmod=0755 /build/target/release/ro-git-server /usr/local/bin/ro-git-server
COPY --from=builder /build/dist /app/dist
COPY --chmod=0755 scripts/git-auto-shell /usr/local/bin/git-auto-shell
COPY --chmod=0755 scripts/git-sync-users /usr/local/bin/git-sync-users
COPY --chmod=0755 scripts/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
COPY --chmod=0644 config/sshd_config /etc/ssh/sshd_config

ENV RO_GIT_LISTEN_ADDR=0.0.0.0:8080 \
    RO_GIT_ROOT=/ \
    RO_GIT_SSH_HOST=localhost \
    RO_GIT_STATIC_DIR=/app/dist \
    RO_GIT_MAX_TOKEN_TTL_SECS=2592000 \
    RO_GIT_NOBODY_UID=65534

EXPOSE 22 8080

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
