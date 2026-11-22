# Gateway apps

Each `<name>.json` is one Gemini custom app, served at `https://<mcp_domain>/<name>/mcp`
by its own gateway container (`GATEWAY_APP=<name>`). Apps share the Google login but
nothing else: each has its own signing key, OAuth storage volume and env file.

An app combines built-in tool sets and proxied MCP servers:

```jsonc
{
  // Built-in tool sets (gateway code). "sandbox" = OpenShell sandboxes (sandbox_tools.py).
  "builtins": ["sandbox"],
  "mcpServers": {
    // Remote: https only; secrets only via ${UPSTREAM_*} from this app's env file
    "github": {
      "url": "https://api.githubcopilot.com/mcp/",
      "headers": { "Authorization": "Bearer ${UPSTREAM_GITHUB_PAT}" }
    },
    // stdio: allowlisted launcher (uvx), pinned version, explicit env only
    "time": { "command": "uvx", "args": ["mcp-server-time==2026.11.11"], "env": {} }
  }
}
```

Tools are prefixed with their namespace (`sandbox_create`, `github_...`).

Adding an app `foo`:
1. `apps/foo.json`
2. a `gw-foo` service in `services/compose.yaml` (copy `gw-sandbox`, minus the OpenShell bits it doesn't need)
3. `import mcp_app foo gw-foo:8000` in `services/Caddyfile`
4. an entry in `mcp_apps` in `ansible/group_vars/all.yml` (its `env`, plus any secrets)
5. a Google OAuth redirect URI `https://<mcp_domain>/foo/auth/callback` (no DNS change)
