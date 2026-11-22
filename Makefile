SHELL := /bin/bash
INFRA := infra
ANSIBLE := ansible

.PHONY: help tools infra-init infra-plan infra-apply deps ssh-open ssh-close deploy deploy-stack secrets check local-up local-sandbox-e2e local-test local-smoke local-down local-ansible

help:
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-14s %s\n", $$1, $$2}'

tools: ## Install local tooling (macOS)
	brew install opentofu ansible sops age

infra-init: ## tofu init
	tofu -chdir=$(INFRA) init

infra-plan: ## tofu plan (needs HCLOUD_TOKEN)
	@test -n "$$HCLOUD_TOKEN" || (echo "export HCLOUD_TOKEN first" && exit 1)
	tofu -chdir=$(INFRA) plan -out=tfplan

infra-apply: ## Apply the saved plan
	tofu -chdir=$(INFRA) apply tfplan && rm -f $(INFRA)/tfplan

deps: ## Install Ansible collections
	cd $(ANSIBLE) && ansible-galaxy collection install -r requirements.yml

# SSH is closed at the Hetzner firewall at rest. These open it to your current public IPv4
# only, via the Hetzner API (no SSH needed, so a changed home IP can never lock you out).
# -target keeps -auto-approve from ever applying unrelated pending infra changes.
ssh-open: ## Open SSH to your current public IPv4 (/32) only
	@ip=$$(curl -4 -fsS --max-time 5 https://checkip.amazonaws.com | tr -d '[:space:]'); \
	[[ $$ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$$ ]] || { echo "could not determine public IPv4"; exit 1; }; \
	echo "Opening SSH to $$ip/32"; \
	tofu -chdir=$(INFRA) apply -auto-approve -input=false -target=hcloud_firewall.this -var "ssh_allowed_cidrs=[\"$$ip/32\"]" && \
	host=$$(tofu -chdir=$(INFRA) output -raw ipv4) && \
	for i in $$(seq 1 30); do nc -z -w 2 $$host 22 2>/dev/null && { echo "SSH reachable on $$host"; exit 0; }; sleep 2; done; \
	echo "SSH still unreachable on $$host after 60s (firewall propagation?)"; exit 1

ssh-close: ## Close SSH again
	tofu -chdir=$(INFRA) apply -auto-approve -input=false -target=hcloud_firewall.this -var 'ssh_allowed_cidrs=[]'

deploy: ## Open SSH, full converge, close SSH (closes even if Ansible fails)
	@$(MAKE) --no-print-directory ssh-open
	@trap '$(MAKE) --no-print-directory ssh-close' EXIT; cd $(ANSIBLE) && ansible-playbook site.yml --diff

deploy-stack: ## Same, but only redeploy the MCP stack
	@$(MAKE) --no-print-directory ssh-open
	@trap '$(MAKE) --no-print-directory ssh-close' EXIT; cd $(ANSIBLE) && ansible-playbook site.yml --diff --tags stack

secrets: ## Edit encrypted secrets
	sops secrets/secrets.sops.yaml

check: ## Static checks + offline plan tests
	tofu -chdir=$(INFRA) fmt -check -recursive
	tofu -chdir=$(INFRA) validate
	tofu -chdir=$(INFRA) test
	cd $(ANSIBLE) && ansible-playbook -i localhost, site.yml --syntax-check
	python3 -B -c 'import ast,sys; [ast.parse(open(f).read(), f) for f in sys.argv[1:]]' services/gateway/*.py

LOCAL_COMPOSE := docker compose -f services/compose.yaml -f local/compose.local.yaml --env-file local/.env

local-up: ## Run the stack locally at https://localhost:8443/sandbox/mcp
	@test -f local/.env || cp local/.env.example local/.env
	@grep -q '^OPENSHELL_DATA_DIR=' local/.env || echo "OPENSHELL_DATA_DIR=$(PWD)/local/.tmp/openshell-data" >> local/.env
	@test -f local/.env.sandbox || printf 'GATEWAY_JWT_SIGNING_KEY=%s\nSANDBOX_PUSH_REPOS=octocat/Hello-World\nSANDBOX_ATTACH_GITHUB=true\n' "$$(openssl rand -hex 32)" > local/.env.sandbox
	@# Well-formed FAKE token: exercises the provider path; GitHub rejects it.
	@test -f local/.env.openshell-setup || printf 'GITHUB_TOKEN=github_pat_11FAKEFAKEFAKE0%s\n' "$$(openssl rand -hex 36)" > local/.env.openshell-setup
	$(LOCAL_COMPOSE) up -d --build --wait

local-sandbox-e2e: ## Drive the sandbox MCP tools against the local OpenShell (create/exec/pip/git/delete)
	docker compose -f services/compose.yaml -f local/compose.local.yaml --env-file local/.env exec -T gw-sandbox \
	  python - < local/sandbox_e2e.py

local-test: ## Gateway unit/integration tests inside the hardened image
	$(LOCAL_COMPOSE) build gw-sandbox
	docker run --rm --read-only --tmpfs /tmp --tmpfs /data:exec,uid=10001,gid=10001 --cap-drop ALL \
	  --security-opt no-new-privileges:true -v $(PWD)/services/gateway/test_gateway.py:/app/test_gateway.py:ro \
	  mcp-gateway:local python test_gateway.py

local-smoke: ## OAuth/MCP smoke test against the local stack
	@docker cp mcp-caddy-1:/data/caddy/pki/authorities/local/root.crt local/.tmp-caddy-root.crt
	local/smoke.sh https://localhost:8443/sandbox local/.tmp-caddy-root.crt; rc=$$?; rm -f local/.tmp-caddy-root.crt; exit $$rc

local-down: ## Stop the local stack
	$(LOCAL_COMPOSE) down

local-ansible: ## Converge the playbook against a disposable Ubuntu 24.04 container
	local/ansible-test.sh
