# Personal MCP host

A single Hetzner VM that gives gemini.google.com code sandboxes over MCP. The sandboxes can test code and push branches and PRs to the GitHub repos you allow.

```
Gemini app "sandbox" ─OAuth─▶ https://<mcp_domain>/sandbox/mcp ─▶ gw-sandbox ─mTLS─▶ OpenShell gateway ─▶ sandboxes
                      └─ Google login, your email only                                  (Docker, Landlock, seccomp,
                                                                                         default-deny egress proxy)
Public: 80/443 only (Caddy). SSH: closed at the Hetzner firewall; opened to your current /32
only while `make deploy` runs (via the Hetzner API, no tunnel/VPN).
DNS: stays at your current provider; only A/AAAA for the MCP subdomain (e.g. mcp.example.com).
```

Reading GitHub from Gemini is covered by Gemini's own read-only GitHub connector. This box adds the writable part.

| Layer | Tool | Where |
|---|---|---|
| Provisioning | OpenTofu + hcloud | `infra/` |
| Config | Ansible | `ansible/` |
| Secrets | Environment variables on the deploying machine (e.g. `op run`), never in the repo | `deploy.env.example` |
| Runtime | Docker Compose | `services/` |
| Sandboxes | [NVIDIA OpenShell](https://github.com/NVIDIA/OpenShell) 0.1.8 (gateway, SDK and images pinned together) | `services/openshell/`, `services/sandbox-image/`, `services/gateway/sandbox_tools.py` |

## Sandboxes

**Tools** in the `sandbox` app: `sandbox_create`, `sandbox_list`, `sandbox_exec` (bash), `sandbox_write_file`, `sandbox_read_file`, `sandbox_delete`.

**Workload image** (`services/sandbox-image`): Ubuntu 24.04 with git, gh, python3, venv/pip, node/npm and build-essential. Commands run as the unprivileged `ubuntu` user. Limits: 1 CPU and 1.5 GiB per sandbox, at most 2 sandboxes, each deleted automatically after 24 h. Sized for a CAX11 (4 GB): the stack itself peaks around 330 MiB. For heavy builds, raise `SANDBOX_MEMORY` and lower `SANDBOX_MAX` so their product stays under about 3 GiB, or upsize `server_type`.

**Network** is default-deny. A sandbox can reach only:

| What | Who (process) | Access |
|---|---|---|
| GitHub (`github.com`, `api.github.com`) | `git`, `gh` | Read-only: clone, fetch, REST/GraphQL reads |
| Repos in `sandbox_push_repos` | `git` | Push (`git-receive-pack`) |
| Repos in `sandbox_push_repos` | `gh` | Create/update PRs, comment |
| PyPI, npm registry | `python3`, `node` | Read-only |

Everything else is blocked: other hosts, `curl` to the registries, and writes to other repos or non-PR writes.

**The GitHub PAT never enters a sandbox.** Sandboxes see an opaque placeholder in `GITHUB_TOKEN`/`GH_TOKEN`. OpenShell's proxy swaps in the real token only for the GitHub endpoints and processes above. The PAT only exists in `.env.openshell-setup`, which is read by a one-shot setup job that registers it with OpenShell. The internet-facing `gw-sandbox` never holds it.

**Fixed by config, not by Gemini.** The agent decides what runs inside a sandbox. Image, credentials, network policy and limits come only from deploy-time config. MCP calls can't change them.

## First deploy

```bash
make tools && make deps
ssh-keygen -t ed25519 -f ~/.ssh/mcp_vps -C mcp-vps   # dedicated admin key (tfvars + inventory point here)
```

1. **Google OAuth app.** In Google Cloud console, create an OAuth client of type *Web application* with redirect URI `https://<mcp_domain>/sandbox/auth/callback`.
   - Set the consent screen to *External / Testing* and add only your own account as a test user. That is a second layer of single-user enforcement.
   - Testing mode is fine long-term. Google only expires refresh tokens after 7 days for apps that request more than openid/email/profile, and the gateway requests only those.
2. **GitHub PAT.** Create a fine-grained PAT scoped to the repos you'll list in `sandbox_push_repos`, with **Contents: read/write** and **Pull requests: read/write** only (no Workflows, no Administration).
   - Turn on **branch protection for `main`** in those repos, so sandbox work always lands through a PR you merge.
3. **Secrets.** Ansible reads them from the environment as `MCP_GOOGLE_OAUTH_CLIENT_ID`, `MCP_GOOGLE_OAUTH_CLIENT_SECRET`, `MCP_GATEWAY_JWT_SIGNING_KEY` (`openssl rand -hex 32`) and optionally `MCP_GITHUB_PAT`. `make deploy` refuses to start (before opening SSH) if a required one is missing.
   - Recommended: store them in a 1Password item, `cp deploy.env.example deploy.env` (gitignored, holds only `op://` references), and run `op run --env-file=deploy.env -- make deploy`.
   - In CI: set the same names as CI secrets.
4. **Infra.** `cp infra/terraform.tfvars.example infra/terraform.tfvars`, export `HCLOUD_TOKEN`, then run `make infra-init infra-plan infra-apply`. That creates the server and the firewall, with SSH closed.
5. **DNS (at your current provider).** Add `A` and `AAAA` records for the MCP subdomain (e.g. `mcp`) with the values from `tofu -chdir=infra output dns_records`. Wait until `dig +short mcp.<your-domain>` returns the server IP.
   - Optional hardening: if your provider supports CAA, add `0 issue "letsencrypt.org"` and `0 issue "sectigo.com"` on the subdomain.
6. **Ansible.** Copy `ansible/inventory/hosts.yml.example` to `hosts.yml` with `tofu -chdir=infra output -raw ipv4`. Copy `ansible/inventory/host_vars/mcp.yml.example` to `mcp.yml` and set `mcp_domain: mcp.<your-domain>`, `allowed_email`, `acme_email` and `sandbox_push_repos`. Both files are gitignored, so your domain and emails stay out of the public repo, and the deploy refuses to run while `example.com` placeholders are left. Then run `make deploy`.
   - The deploy opens 22 to your IP, converges, and closes 22.
   - The first deploy pulls about 1.5 GB of images and builds the sandbox image, so allow a few minutes.
7. **Verify push with the real PAT** (the local tests can only use a fake token). In Gemini, ask the sandbox to clone one of your repos, commit on a branch, push it, and open a PR.
8. **Gemini.** Go to gemini.google.com → Settings → Connected Apps → Custom apps → *Add a custom app*. Enter `https://<mcp_domain>/sandbox/mcp`, approve the gateway's consent page, sign in with Google, then call `whoami`.
   - Google's help page lists restrictions (personal account, 18+, US, English, history on), but custom connectors work from a personal account in Europe.
   - Leave Gemini's *Advanced settings* (client ID/secret) empty. Gemini registers itself (DCR) as a public PKCE client, listing six redirect URIs on three Google hosts; `allowed_client_redirect_uris` allows exactly those.
   - If Gemini says the redirect URL was rejected, run `make logs`. The gateway logs every refused registration with the URIs it asked for (`client registration refused`).

## Local testing

| Command | What it proves |
|---|---|
| `make check` | `tofu fmt`/`validate`, 3 offline plan tests (mocked provider: firewall surface, scoped just-in-time SSH, world-open SSH rejected), Ansible syntax, Python syntax |
| `make local-up` | Full stack, including a real OpenShell gateway, at `https://localhost:8443/sandbox/mcp` (Caddy internal CA, dummy Google creds, fake PAT) |
| `make local-smoke` | The OAuth discovery chain a spec-compliant client follows (14 checks): 401 + resource metadata, path-inserted AS metadata, PKCE, DCR, the redirect allowlist, authorize → consent, forged token rejected |
| `make local-test` | Gateway tests inside the hardened image: single-user enforcement, app selection, config attack inputs, a real `uvx` stdio backend, and sandbox adapter safety against a fake OpenShell (ownership, sizes, argv-only paths, TTL reap, limit, repo-scoped policy) |
| `make local-sandbox-e2e` | The sandbox MCP tools against real OpenShell (16 checks): create; write, pip install and run; git clone; token is only a placeholder; egress blocked; non-PR writes denied; PR creation on an allowlisted repo passes policy; foreign/bad names rejected; delete |
| `make local-ansible` | Converges `site.yml` twice against a systemd Ubuntu 24.04 container. It then asserts sshd, ufw, env-file perms, the stack and PAT scoping, and runs the sandbox e2e on the converged host |

None of this exercises a real Google login, a real PAT push, or Gemini itself; that is steps 7–8 above.

## Apps and backends

- **To add a backend to an existing app,** edit `services/gateway/apps/<app>.json`, then run `make deploy-stack`.
- **To add a new app** (a separate Gemini toggle), follow the checklist in [services/gateway/apps/README.md](services/gateway/apps/README.md).
- **To change what sandboxes may reach,** edit `build_policy` in `services/gateway/openshell_common.py` (network) or `services/sandbox-image/Dockerfile` (tools).
  - Policy rules match the executable path, so a new tool that needs network access must be named there too.

Rules for backends:

- Remote servers must use `https://`. Credentials come from `${UPSTREAM_*}` env vars that you add under the app's `env` in `mcp_apps`, which writes them only to that app's `.env.<app>`.
- stdio servers can only use allowlisted launchers (`uvx`). Pin package versions. They get only the env you list explicitly, plus an enforced policy that keeps uv on the image's Python.
- A backend that fails to start is logged and skipped; the gateway and the other backends keep running.

## Security model

- **Single identity.** The gateway rejects any token whose Google email isn't `allowed_email`. It fails closed: if the email claim is missing, the request is rejected too.
- **No token passthrough.** Gemini's token stops at the gateway, as the MCP authorization spec requires.
- **Client redirect allowlist.** OAuth clients can only register redirect URIs matching `allowed_client_redirect_uris` (https only). On top of that, every authorization goes through a consent page.
- **Gateway-signed tokens** use a per-app key derived from `gateway_jwt_signing_key`. Rotating the master revokes every session.
- **The OpenShell gateway controls the host Docker socket**, so treat it as root:
  - It's on no internet-facing network: an internal Compose network, plus host loopback for sandbox callbacks.
  - Every API call needs a client certificate from its own CA. Only `gw-sandbox` and the setup job have one, mounted read-only from the `openshell_client` volume.
  - Upstream's default is plaintext with no auth; this setup turns mTLS on.
- **Sandbox isolation** is OpenShell's: containers with Landlock and seccomp, an unprivileged user, and an L7 policy proxy for all egress. gVisor is installed on the host, but OpenShell's Docker driver doesn't use it.
- **Secrets** never touch the repo. Ansible reads them from the deploying machine's environment and writes them root-only (0600) to `/opt/mcp/`:
  - `.env`: the shared Google client and allowlists
  - `.env.sandbox`: the app's signing key and sandbox settings
  - `.env.openshell-setup`: the PAT
- **Containers** run with no-new-privileges. The gateway containers drop all capabilities and have read-only root filesystems.
- **Docker vs ufw.** Published ports bypass ufw. Only Caddy publishes publicly; the OpenShell port is bound to 127.0.0.1.
- **Admin access without a VPN.** Port 22 is closed at the Hetzner firewall at rest.
  - `make ssh-open`/`deploy` add one rule for your current IPv4 `/32` through the Hetzner API, and `make ssh-close` removes it. `deploy` closes it even if Ansible fails.
  - sshd is key-only, with no root login, and only `ops` may log in. ufw rate-limits port 22.
- **Prompt injection is the realistic threat.** A sandbox can push to your allowlisted repos, so anything the agent reads (issues, READMEs, web content) could steer what it pushes. Branch protection plus reviewing every PR is the control; the policy limits the blast radius to those repos.

## Not done yet

- [ ] **First real connect from Gemini.** Registration redirect URIs are confirmed (2026-11-24); the login and a `whoami` call still need confirming.
- [ ] **Real-PAT push check** (deploy step 7). The local tests only prove the policy lets PR creation through and blocks other writes.
- Note: OAuth client registrations persist on each app's `gw_<app>_data` volume, so restarts don't force a new login.
- Note: sandboxes are disposable (24 h TTL). Push anything worth keeping.
- [ ] Remote OpenTofu state (Hetzner Object Storage, S3 backend) once there's more than one machine.
- [ ] Backups. Hetzner backups are off (`enable_backups = false`). Nothing on the box is irreplaceable: work lives in your repos, losing OAuth volumes costs one Gemini re-login, and certificates re-issue automatically.
- [ ] Container image freshness. Unattended upgrades patch the host only. Rebuild/pull monthly with `docker compose build --pull && docker compose pull && docker compose up -d`. Bump OpenShell by changing all four pins together: the gateway image, the supervisor and sandbox images in `gateway.toml`, and `openshell` in `requirements.txt`.
- [ ] Uptime/expiry alerting, e.g. an external check on `https://<mcp_domain>/sandbox/healthz`.
- Note: the host reboots itself for kernel updates at 04:30 UTC; containers come back on their own.
- Note: if the server is ever recreated, its IPs change; update the `A`/`AAAA` records at your registrar.
