#!/usr/bin/env bash
# Converge the real playbook against a disposable systemd Ubuntu 24.04 container, twice.
# Uses a throwaway SSH key under local/.tmp (gitignored) and dummy secrets passed through
# the same MCP_* env vars a real deploy uses.
# Usage: local/ansible-test.sh [--keep]
set -euo pipefail
cd "$(dirname "$0")/.."

TMP=local/.tmp
NAME=mcp-ansible-target
PORT=2222
mkdir -p "$TMP"

# Throwaway SSH key
[[ -f $TMP/id_ed25519 ]] || ssh-keygen -q -t ed25519 -N '' -C ansible-test -f "$TMP/id_ed25519"
cp "$TMP/id_ed25519.pub" local/ansible-target/authorized_keys

# Dummy secrets via the real env interface (fixed for both runs so run #2 stays idempotent).
# The PAT is well-formed but FAKE: it exercises the provider path; GitHub rejects it.
export MCP_GOOGLE_OAUTH_CLIENT_ID=dummy.apps.googleusercontent.com
export MCP_GOOGLE_OAUTH_CLIENT_SECRET=dummy-secret
export MCP_GATEWAY_JWT_SIGNING_KEY=$(openssl rand -hex 32)
export MCP_GITHUB_PAT=github_pat_11HARNESSFAKE0harnessfakeharnessfakeharnessfakeharnessfakeharnessfake

# Fresh target
docker rm -f "$NAME" >/dev/null 2>&1 || true
docker build -q -t mcp-ansible-target local/ansible-target >/dev/null
docker run -d --name "$NAME" --privileged --cgroupns=host \
  -v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run --tmpfs /run/lock \
  -v /var/lib/docker -v /var/lib/containerd \
  -p 127.0.0.1:$PORT:22 mcp-ansible-target >/dev/null
for _ in $(seq 1 30); do nc -z 127.0.0.1 $PORT 2>/dev/null && break; sleep 1; done

cat >"$TMP/hosts.yml" <<EOF
all:
  hosts:
    mcp:
      ansible_host: 127.0.0.1
      ansible_port: $PORT
      ansible_user: ops
      ansible_ssh_private_key_file: $PWD/$TMP/id_ed25519
      # Fresh container = fresh host keys: use a throwaway known_hosts, never ~/.ssh/known_hosts
      ansible_ssh_common_args: -o UserKnownHostsFile=$PWD/$TMP/known_hosts
EOF
rm -f "$TMP/known_hosts"

run_play() {
  (cd ansible && ANSIBLE_HOST_KEY_CHECKING=False \
    ansible-playbook -i "../$TMP/hosts.yml" site.yml -e mcp_domain=localhost \
    -e acme_email=dev@harness.invalid -e allowed_email=you@harness.invalid \
    -e '{"sandbox_push_repos": ["octocat/Hello-World"]}' "$@")
}

echo "== converge #1"; run_play | tee "$TMP/run1.log" | grep -E '^mcp .*ok=|fatal' || true
echo "== converge #2 (idempotence)"; run_play | tee "$TMP/run2.log" | grep -E '^mcp .*ok=|fatal' || true
echo "== tasks changed on run #2:"; grep -B1 -E '^changed:' "$TMP/run2.log" | grep -E '^(TASK|RUNNING HANDLER)' || echo "(none)"
grep -qE 'failed=0' "$TMP/run1.log" && grep -qE 'failed=0' "$TMP/run2.log"

echo "== host assertions"
docker exec "$NAME" bash -c '
  set -e
  sshd -T | grep -E "^(permitrootlogin|passwordauthentication|allowusers) "
  ufw status verbose | sed -n "1,4p"
  docker compose -p mcp ps -a --format "{{.Service}}: {{.Status}}" | sort
  stat -c "%a %U %n" /opt/mcp/.env /opt/mcp/.env.sandbox /opt/mcp/.env.openshell-setup
  systemctl is-active apt-daily-upgrade.timer
  ufw status | grep -E "^22/tcp"
  curl -s -o /dev/null -w "sandbox app via caddy (inside host): %{http_code}\n" --resolve localhost:443:127.0.0.1 -k https://localhost/sandbox/healthz
  # OpenShell gateway: loopback only on the host, mTLS required
  ss -ltnH "sport = :8080" | awk "{print \"openshell gateway listens on: \" \$4}"
  # PAT scoping: only in .env.openshell-setup; not in the internet-facing gateway, Caddy or other env files
  PAT=$(sed -n "s/^GITHUB_TOKEN=//p" /opt/mcp/.env.openshell-setup)
  test -n "$PAT" && echo "PAT in .env.openshell-setup: yes"
  for c in mcp-gw-sandbox-1 mcp-caddy-1 mcp-openshell-gateway-1; do
    docker inspect -f "{{range .Config.Env}}{{println .}}{{end}}" $c | grep -qF "$PAT" && echo "PAT LEAKED to $c!" || echo "PAT in $c env: no"
  done
  grep -qF "$PAT" /opt/mcp/.env /opt/mcp/.env.sandbox && echo "PAT LEAKED to shared/app env!" || echo "PAT in .env/.env.sandbox: no"
'

echo "== sandbox e2e on the converged host (real OpenShell, nested Docker)"
docker exec -i "$NAME" bash -c "cd /opt/mcp && docker compose exec -T gw-sandbox python -" < local/sandbox_e2e.py \
  | grep -E "^(PASS|FAIL|----)"

[[ "${1:-}" == "--keep" ]] || docker rm -f "$NAME" >/dev/null
rm -f local/ansible-target/authorized_keys
