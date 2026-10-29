.PHONY: help test check test-issues test-ssh test-rust proto issues issues-ready issues-ui clean docker-build docker-prod docker-test docker-shell docker-yolo

PROJECT_NAME ?= ro-git
DOCKER_IMAGE ?= $(PROJECT_NAME)-workspace:latest
PROD_IMAGE ?= $(PROJECT_NAME):latest
CONTAINER_NAME ?= agy-ro-git
DATA_VOLUME ?= agy-data-$(PROJECT_NAME)

help: ## Show this help message
	@echo "Available targets:"
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

test: test-issues test-ssh test-rust ## Run full verification suite (issue tooling + SSH provisioning + Rust workspace)

check: test ## Alias for test

test-issues: ## Run unit tests for git issue tracker CLI and server
	python3 tests/test_issue_tooling.py

test-ssh: ## Run unit and integration tests for SSH config, git-auto-shell, and git-sync-users
	python3 tests/test_ssh_provisioning.py

test-rust: ## Run Rust workspace tests, WASM target check, and clippy lints
	cargo test --workspace
	cargo check --manifest-path crates/ro-git-ui/Cargo.toml --target wasm32-unknown-unknown
	cargo clippy --workspace -- -D warnings

proto: ## Regenerate roto Protobuf views, builders, and roto-grpc service traits
	cargo roto --manifest-path crates/ro-git-proto/Cargo.toml


issues: ## List git issues in tabular format
	@python3 scripts/issue.py list

issues-ready: ## List open issues ready for pickup (no blockers)
	@python3 scripts/issue.py ready

issues-ui: ## Launch read-only issue browser Web UI on port 8080
	python3 scripts/issue_server.py --port 8080

clean: ## Clean generated test caches and temporary files
	rm -rf __pycache__ tests/__pycache__ scripts/__pycache__ target dist

docker-build: ## Build containerized development Docker image
	docker build --target workspace -t $(DOCKER_IMAGE) .

docker-prod: ## Build production Docker image (sshd + git-auto-shell + ro-git-server + WASM UI)
	docker build --target production -t $(PROD_IMAGE) .

docker-test: ## Run test suite inside container
	docker run --rm -v $(CURDIR):/workspace -w /workspace $(DOCKER_IMAGE) make test

docker-shell: ## Launch interactive shell inside container
	docker run --rm -it \
		-v $(CURDIR):/workspace \
		-v $(DATA_VOLUME):/home/developer/.gemini/antigravity-cli \
		-v $(HOME)/.gemini/antigravity-cli/antigravity-oauth-token:/home/developer/.gemini/antigravity-cli/antigravity-oauth-token:ro \
		-w /workspace \
		$(DOCKER_IMAGE) /bin/bash

docker-yolo: ## Launch containerized Antigravity daemon in isolated YOLO mode
	docker rm -f $(CONTAINER_NAME) 2>/dev/null || true
	docker run -d --name $(CONTAINER_NAME) \
		-v $(CURDIR):/workspace \
		-v $(DATA_VOLUME):/home/developer/.gemini/antigravity-cli \
		-v $(HOME)/.gemini/antigravity-cli/antigravity-oauth-token:/home/developer/.gemini/antigravity-cli/antigravity-oauth-token:ro \
		-w /workspace \
		$(DOCKER_IMAGE) \
		bash -c '\
			mkdir -p ~/.gemini/config/projects ~/.gemini/antigravity-cli && \
			printf "%s\n" "{\"userSettings\": {\"cliRemoteControlHostname\": \"$(PROJECT_NAME)-sandbox\", \"remoteControlHostname\": \"$(CONTAINER_NAME)\", \"autoExecutionPolicy\": \"always-proceed\", \"globalPermissionGrants\": {\"allow\": [\"command(*)\", \"read_url(*)\", \"mcp(*)\"]}}}" > ~/.gemini/config/config.json && \
			printf "%s\n" "{\"id\": \"$(PROJECT_NAME)\", \"name\": \"$(PROJECT_NAME)\", \"projectResources\": {\"resources\": [{\"gitFolder\": {\"folderUri\": \"file:///workspace\", \"defaultBranch\": \"main\"}}]}, \"settings\": {}, \"isWorkspaceOnly\": false}" > ~/.gemini/config/projects/$(PROJECT_NAME).json && \
			printf "%s\n" "{\"autoExecutionPolicy\": \"always-proceed\", \"trustedWorkspaces\": [\"/workspace\", \"/tmp\", \"/home/developer\"]}" > ~/.gemini/antigravity-cli/settings.json && \
			exec agy --dangerously-skip-permissions remote-control serve'
