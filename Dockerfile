# check=skip=SecretsUsedInArgOrEnv
# ---------------------------------------------------------------------------
# Stage 1: Multi-arch toolchain (linux/amd64 and linux/arm64)
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim AS toolchain

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        curl \
        git \
        openssh-client \
        openssh-server \
        python3 \
        protobuf-compiler \
        libprotobuf-dev \
        pkg-config \
        libssl-dev && \
    rm -rf /var/lib/apt/lists/*

ENV RUSTUP_HOME=/opt/rustup \
    CARGO_HOME=/opt/cargo \
    PATH=/opt/cargo/bin:/usr/local/bin:$PATH \
    PROTOC=/usr/bin/protoc \
    PROTOC_INCLUDE=/usr/include

ARG TRUNK_VERSION="0.21.14"
ARG WASM_BINDGEN_VERSION="0.2.128"
ARG BINARYEN_VERSION="130"

RUN mkdir -p /opt/cargo /opt/rustup && \
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
        sh -s -- -y --default-toolchain stable --profile minimal --component rustfmt,clippy --target wasm32-unknown-unknown && \
    arch="$(uname -m)" && \
    case "$arch" in \
        aarch64|arm64) \
            trunk_arch="aarch64-unknown-linux-gnu" && \
            wbg_arch="aarch64-unknown-linux-gnu" && \
            binaryen_arch="aarch64-linux" \
            ;; \
        x86_64|amd64) \
            trunk_arch="x86_64-unknown-linux-gnu" && \
            wbg_arch="x86_64-unknown-linux-musl" && \
            binaryen_arch="x86_64-linux" \
            ;; \
        *) \
            printf 'Unsupported architecture: %s\n' "$arch" >&2 && exit 1 \
            ;; \
    esac && \
    curl -fSL "https://github.com/trunk-rs/trunk/releases/download/v${TRUNK_VERSION}/trunk-${trunk_arch}.tar.gz" | \
        tar -xz -C /usr/local/bin trunk && \
    curl -fSL "https://github.com/wasm-bindgen/wasm-bindgen/releases/download/${WASM_BINDGEN_VERSION}/wasm-bindgen-${WASM_BINDGEN_VERSION}-${wbg_arch}.tar.gz" | \
        tar -xz --strip-components=1 -C /usr/local/bin && \
    curl -fSL "https://github.com/WebAssembly/binaryen/releases/download/version_${BINARYEN_VERSION}/binaryen-version_${BINARYEN_VERSION}-${binaryen_arch}.tar.gz" | \
        tar -xz --strip-components=2 -C /usr/local/bin "binaryen-version_${BINARYEN_VERSION}/bin/wasm-opt" && \
    chmod -R a+rwX /opt/rustup /opt/cargo

# ---------------------------------------------------------------------------
# Stage 2: Development workspace image (roto codegen + agy CLI + dev user)
# ---------------------------------------------------------------------------
FROM toolchain AS workspace

RUN cargo install --git https://github.com/chathaway-codes/roto \
        cargo-roto \
        protoc-gen-roto \
        protoc-gen-roto-grpc && \
    chmod -R a+rwX /opt/rustup /opt/cargo

ARG AGY_VERSION="1.2.16-5594158052802560"
RUN if [ "$(uname -m)" = "x86_64" ]; then \
        curl -fSL "https://storage.googleapis.com/antigravity-public/antigravity-cli/${AGY_VERSION}/linux-x64/cli_linux_x64.tar.gz" | \
        tar -xz -C /tmp && \
        install -Dm755 /tmp/antigravity /usr/bin/agy && \
        rm -f /tmp/antigravity; \
    fi

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
# Stage 3: Build release server binary and Yew WASM frontend assets
# ---------------------------------------------------------------------------
FROM toolchain AS builder

WORKDIR /build

COPY Cargo.toml Cargo.lock ./
COPY proto ./proto
COPY crates ./crates

RUN cargo build --release --locked -p ro-git-server && \
    trunk build --release --config crates/ro-git-ui/Trunk.toml --dist /build/dist

# ---------------------------------------------------------------------------
# Stage 4: Minimal production runtime (sshd + git-auto-shell + ro-git-server)
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim AS production

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        git \
        openssh-server \
        python3 \
        libssl3 && \
    rm -rf /var/lib/apt/lists/* && \
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
