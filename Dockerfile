FROM archlinux:latest

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
