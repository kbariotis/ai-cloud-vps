"""Personal MCP gateway (FastMCP 4.x).

- OAuth front door for Gemini: FastMCP's Google provider (an OAuth proxy) serves the MCP
  authorization surface — protected-resource metadata, CIMD + DCR client registration,
  authorize/consent, token — backed by one Google OAuth app.
- Single-user: any token whose Google email != ALLOWED_EMAIL is rejected (fail closed).
- Client redirect URIs are restricted to an allowlist (Gemini's callback host).
- One gateway process per Gemini app: GATEWAY_APP picks apps/<name>.json, whose backend
  MCP servers are each mounted under a namespace.
  Gemini's token is never forwarded upstream; upstreams get their own credentials.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
from pathlib import Path
from typing import Any

from fastmcp import FastMCP
from fastmcp.server import create_proxy
from fastmcp.server.auth.providers.google import GoogleProvider
from fastmcp.server.dependencies import get_access_token
from starlette.requests import Request
from starlette.responses import PlainTextResponse

log = logging.getLogger("gateway")

APPS_DIR = Path(__file__).with_name("apps")

# stdio backends are child processes: no shell, fixed launchers only.
# Add "npx" here only after adding Node.js to the Dockerfile.
ALLOWED_STDIO_COMMANDS = frozenset({"uvx"})
# Enforced on every stdio child (config can't override): use the image's Python,
# never download interpreters at runtime.
STDIO_POLICY_ENV = {
    "UV_PYTHON_PREFERENCE": "only-system",
    "UV_PYTHON_DOWNLOADS": "never",
    "UV_NO_PROGRESS": "1",
}
SERVER_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
# Config may only reference UPSTREAM_* env vars, so it can't leak gateway secrets.
ENV_REF_RE = re.compile(r"\$\{(UPSTREAM_[A-Z0-9_]+)\}")
GOOGLE_SCOPES = ["openid", "https://www.googleapis.com/auth/userinfo.email"]
MIN_SIGNING_KEY_LEN = 32


class ConfigError(ValueError):
    pass


def require_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise ConfigError(f"missing required env var {name}")
    return value


def app_servers_file() -> tuple[str, Path]:
    """GATEWAY_APP selects apps/<name>.json baked into the image (name is regex-checked)."""
    app = require_env("GATEWAY_APP")
    if not SERVER_NAME_RE.fullmatch(app):
        raise ConfigError(f"invalid GATEWAY_APP {app!r}")
    path = APPS_DIR / f"{app}.json"
    if not path.is_file():
        raise ConfigError(f"no app config at {path}")
    return app, path


def redirect_allowlist() -> list[str]:
    """Comma-separated redirect URI patterns (FastMCP wildcard syntax), https only."""
    patterns = [p.strip() for p in require_env("ALLOWED_CLIENT_REDIRECT_URIS").split(",") if p.strip()]
    for p in patterns:
        if not p.startswith("https://"):
            raise ConfigError(f"redirect pattern must be https: {p!r}")
    return patterns


def expand_env_refs(value: str) -> str:
    def sub(match: re.Match[str]) -> str:
        var = match.group(1)
        if var not in os.environ:
            raise ConfigError(f"app config references unset env var {var}")
        return os.environ[var]

    if "${" in ENV_REF_RE.sub("", value):
        raise ConfigError(f"only ${{UPSTREAM_*}} env refs are allowed: {value!r}")
    return ENV_REF_RE.sub(sub, value)


def _str_map(raw: Any, field: str, server: str) -> dict[str, str]:
    if raw is None:
        return {}
    if not isinstance(raw, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in raw.items()
    ):
        raise ConfigError(f"{server}.{field} must be a map of strings")
    return {k: expand_env_refs(v) for k, v in raw.items()}


KNOWN_BUILTINS = frozenset({"sandbox"})


def load_builtins(path: Path) -> list[str]:
    """Built-in tool sets an app enables, e.g. {"builtins": ["sandbox"]}."""
    raw = json.loads(path.read_text()).get("builtins", [])
    if not isinstance(raw, list) or not all(isinstance(b, str) for b in raw):
        raise ConfigError("builtins must be a list of strings")
    unknown = sorted(set(raw) - KNOWN_BUILTINS)
    if unknown:
        raise ConfigError(f"unknown builtins: {unknown}")
    return raw


def load_servers(path: Path) -> dict[str, dict[str, Any]]:
    """Validate an apps/<app>.json file. Static, deploy-time config only — never request-driven."""
    raw = json.loads(path.read_text())
    servers = raw.get("mcpServers", {})
    if not isinstance(servers, dict):
        raise ConfigError("mcpServers must be an object")

    out: dict[str, dict[str, Any]] = {}
    for name, cfg in servers.items():
        if not SERVER_NAME_RE.fullmatch(name):
            raise ConfigError(f"invalid server name {name!r}")
        if not isinstance(cfg, dict):
            raise ConfigError(f"{name} must be an object")

        if "url" in cfg:
            url = cfg["url"]
            if not isinstance(url, str) or not url.startswith("https://"):
                raise ConfigError(f"{name}.url must be https://")
            out[name] = {
                "url": url,
                "transport": "http",
                "headers": _str_map(cfg.get("headers"), "headers", name),
            }
        elif "command" in cfg:
            command, args = cfg["command"], cfg.get("args", [])
            if command not in ALLOWED_STDIO_COMMANDS:
                raise ConfigError(f"{name}.command {command!r} not in allowlist")
            if not isinstance(args, list) or not all(isinstance(a, str) for a in args):
                raise ConfigError(f"{name}.args must be a list of strings")
            out[name] = {
                "command": command,
                "args": args,
                # Explicit env only (MCP SDK adds just HOME/PATH/etc.); the child never
                # inherits the gateway's secrets. Policy env wins over config.
                "env": {**_str_map(cfg.get("env"), "env", name), **STDIO_POLICY_ENV},
            }
        else:
            raise ConfigError(f"{name} needs either 'url' or 'command'")
    return out


class SingleUserGoogleProvider(GoogleProvider):
    """Google OAuth proxy that only accepts one identity."""

    def __init__(self, *, allowed_email: str, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._allowed_email = allowed_email.lower()

    # Lowest hook every bearer check goes through:
    # BearerAuthBackend -> verify_token -> load_access_token (OAuthProxy) -> Google verifier.
    async def load_access_token(self, token: str):  # type: ignore[override]
        access = await super().load_access_token(token)
        if access is None:
            return None
        claims = getattr(access, "claims", None) or {}
        email = str(claims.get("email", "")).lower()
        if email != self._allowed_email:
            # Fail closed — also triggers if the provider stops exposing the email claim.
            log.warning("rejected token for identity %r", email or "<none>")
            return None
        return access


def build_server() -> FastMCP:
    app, servers_file = app_servers_file()
    signing_key = require_env("GATEWAY_JWT_SIGNING_KEY")
    if len(signing_key) < MIN_SIGNING_KEY_LEN:
        raise ConfigError(f"GATEWAY_JWT_SIGNING_KEY must be >= {MIN_SIGNING_KEY_LEN} chars")

    auth = SingleUserGoogleProvider(
        allowed_email=require_env("ALLOWED_EMAIL"),
        client_id=require_env("GOOGLE_CLIENT_ID"),
        client_secret=require_env("GOOGLE_CLIENT_SECRET"),
        base_url=require_env("BASE_URL"),
        required_scopes=GOOGLE_SCOPES,
        allowed_client_redirect_uris=redirect_allowlist(),
        # Independent of the Google secret, so rotating that doesn't drop registrations.
        jwt_signing_key=signing_key,
        require_authorization_consent=True,
        enable_cimd=True,
    )
    mcp = FastMCP(f"personal-{app}", auth=auth)

    @mcp.tool
    def whoami() -> dict[str, Any]:
        """Return the identity the gateway authenticated for this request."""
        token = get_access_token()
        claims = (getattr(token, "claims", None) or {}) if token else {}
        return {"email": claims.get("email"), "scopes": getattr(token, "scopes", [])}

    @mcp.custom_route("/healthz", methods=["GET"])
    async def healthz(_: Request) -> PlainTextResponse:
        return PlainTextResponse("ok")

    for name, cfg in load_servers(servers_file).items():
        mcp.mount(create_proxy({"mcpServers": {name: cfg}}, name=name), namespace=name)
        log.info("mounted backend %s (%s)", name, "remote" if "url" in cfg else "stdio")

    for builtin in load_builtins(servers_file):
        if builtin == "sandbox":
            from sandbox_tools import build_sandbox_server  # needs the OpenShell SDK

            mcp.mount(build_sandbox_server(), namespace="sandbox")
        log.info("mounted builtin %s", builtin)

    return mcp


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    try:
        mcp = build_server()
    except ConfigError as exc:
        log.error("config error: %s", exc)
        sys.exit(2)
    # Bound inside the container only; Caddy is the sole ingress.
    mcp.run(transport="http", host="0.0.0.0", port=8000)


if __name__ == "__main__":
    main()
