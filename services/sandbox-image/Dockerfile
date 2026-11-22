# Workload image for OpenShell sandboxes: what the agent's code runs in.
# Same base OpenShell uses by default (ubuntu user uid 1000), plus dev tooling.
# Tool paths matter: the GitHub provider profile only lets /usr/bin/git and /usr/bin/gh
# reach GitHub, so install them from apt (not into /usr/local or a venv).
FROM nvcr.io/nvidia/base/ubuntu:24.04

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates curl gnupg git jq ripgrep unzip make build-essential \
      python3 python3-venv python3-pip pipx \
      nodejs npm \
 && install -d -m 0755 /etc/apt/keyrings \
 && curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg -o /etc/apt/keyrings/githubcli-archive-keyring.gpg \
 && chmod 0644 /etc/apt/keyrings/githubcli-archive-keyring.gpg \
 && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
      > /etc/apt/sources.list.d/github-cli.list \
 && apt-get update && apt-get install -y --no-install-recommends gh \
 && rm -rf /var/lib/apt/lists/*

# Make git use gh's credential helper, which reads the GITHUB_TOKEN placeholder that
# OpenShell swaps for the real token at the proxy (only for allowed GitHub endpoints).
RUN git config --system credential.https://github.com.helper '' \
 && git config --system --add credential.https://github.com.helper '!/usr/bin/gh auth git-credential' \
 && git config --system init.defaultBranch main
