"""MCP tools for OpenShell sandboxes (mounted by gateway.py for apps with "builtins": ["sandbox"]).

The agent decides WHAT runs inside a sandbox; it never decides the sandbox's image,
credentials or network policy. Those come only from deploy-time env:

  OPENSHELL_ENDPOINT, OPENSHELL_TLS_DIR   mTLS connection to the OpenShell gateway
  SANDBOX_IMAGE                           workload image (git, gh, python, node)
  SANDBOX_PUSH_REPOS                      owner/repo,... the sandboxes may push to / open PRs on
  SANDBOX_MAX (3), SANDBOX_TTL_HOURS (24), SANDBOX_CPU ("2"), SANDBOX_MEMORY ("4Gi")
"""

from __future__ import annotations

import logging
import os
import re
import secrets
import time
from functools import partial
from typing import Any

import anyio
import grpc
from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from google.protobuf import struct_pb2
from openshell import GatewayError, SandboxClient
from openshell._proto import openshell_pb2 as pb

from openshell_common import (
    GITHUB_PROVIDER,
    WORKSPACE,
    OpenShellConfigError,
    build_policy,
    client_from_env,
    parse_push_repos,
    status_of,
)

log = logging.getLogger("gateway.sandbox")

OWNER_LABEL = "managed-by"
OWNER_VALUE = "mcp-gateway"
CREATED_LABEL = "mcp-created-at"
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,40}$")
WORKDIR = "/sandbox"
MAX_OUTPUT = 64 * 1024  # per stream returned to the client
MAX_WRITE = 1024 * 1024  # OpenShell buffers at most 4 MiB of stdin per exec
MAX_READ = 256 * 1024
MAX_TIMEOUT = 600


class Settings:
    def __init__(self) -> None:
        self.image = os.environ.get("SANDBOX_IMAGE", "").strip()
        if not self.image:
            raise OpenShellConfigError("missing SANDBOX_IMAGE")
        self.push_repos = parse_push_repos(os.environ.get("SANDBOX_PUSH_REPOS", ""))
        self.max_sandboxes = int(os.environ.get("SANDBOX_MAX", "3"))
        self.ttl_seconds = int(float(os.environ.get("SANDBOX_TTL_HOURS", "24")) * 3600)
        self.cpu = os.environ.get("SANDBOX_CPU", "2")
        self.memory = os.environ.get("SANDBOX_MEMORY", "4Gi")
        # false when no PAT is configured (openshell-setup then creates no provider).
        self.attach_github = os.environ.get("SANDBOX_ATTACH_GITHUB", "true").strip().lower() == "true"
        self.policy = build_policy(self.push_repos)


def _truncate(text: str) -> tuple[str, bool]:
    data = text.encode()
    if len(data) <= MAX_OUTPUT:
        return text, False
    return data[:MAX_OUTPUT].decode(errors="ignore") + "\n…[truncated]", True


def _slug(hint: str | None) -> str:
    base = re.sub(r"[^a-z0-9-]+", "-", (hint or "box").lower()).strip("-")[:20] or "box"
    return f"{base}-{secrets.token_hex(3)}"


class SandboxBackend:
    """Synchronous OpenShell operations; tools call these in a worker thread."""

    def __init__(self, settings: Settings, client: SandboxClient) -> None:
        self.s = settings
        self.c = client

    def _ours(self) -> list[Any]:
        return self.c.list_all(workspace=WORKSPACE, label_selector=f"{OWNER_LABEL}={OWNER_VALUE}")

    def _require_ours(self, name: str) -> None:
        if not NAME_RE.fullmatch(name):
            raise ToolError("invalid sandbox name")
        try:
            ref = self.c.get(name, workspace=WORKSPACE)
        except GatewayError as exc:
            if status_of(exc) == grpc.StatusCode.NOT_FOUND:
                raise ToolError(f"no sandbox named {name!r}") from None
            raise
        if (ref.labels or {}).get(OWNER_LABEL) != OWNER_VALUE:
            raise ToolError(f"no sandbox named {name!r}")  # don't reveal foreign sandboxes

    def _reap_expired(self) -> list[str]:
        now = int(time.time())
        reaped = []
        for ref in self._ours():
            created = int((ref.labels or {}).get(CREATED_LABEL, "0") or 0)
            if now - created > self.s.ttl_seconds:
                self.c.delete(ref.name, workspace=WORKSPACE, allow_missing=True)
                reaped.append(ref.name)
        if reaped:
            log.info("reaped expired sandboxes: %s", reaped)
        return reaped

    def create(self, name_hint: str | None) -> dict[str, Any]:
        self._reap_expired()
        live = self._ours()
        if len(live) >= self.s.max_sandboxes:
            raise ToolError(
                f"sandbox limit reached ({self.s.max_sandboxes}); delete one first: "
                + ", ".join(r.name for r in live)
            )
        name = _slug(name_hint)
        resources = struct_pb2.Struct()
        resources.update({"limits": {"cpu": self.s.cpu, "memory": self.s.memory}})
        spec = pb.SandboxSpec(
            providers=[GITHUB_PROVIDER] if self.s.attach_github else [],
            policy=self.s.policy,
            template=pb.SandboxTemplate(image=self.s.image, resources=resources),
        )
        labels = {OWNER_LABEL: OWNER_VALUE, CREATED_LABEL: str(int(time.time()))}
        self.c.create(workspace=WORKSPACE, name=name, spec=spec, labels=labels)
        self.c.wait_ready(name, workspace=WORKSPACE, timeout_seconds=300)
        return {
            "sandbox": name,
            "workdir": WORKDIR,
            "push_repos": self.s.push_repos,
            "expires_in_hours": round(self.s.ttl_seconds / 3600, 1),
        }

    def list(self) -> list[dict[str, Any]]:
        now = int(time.time())
        out = []
        for ref in self._ours():
            created = int((ref.labels or {}).get(CREATED_LABEL, "0") or 0)
            phase = getattr(getattr(ref, "status", None), "phase", None)
            out.append({"sandbox": ref.name, "phase": str(phase), "age_minutes": (now - created) // 60})
        return out

    def exec(self, name: str, command: str, workdir: str, timeout_seconds: int) -> dict[str, Any]:
        self._require_ours(name)
        timeout = max(1, min(int(timeout_seconds), MAX_TIMEOUT))
        res = self.c.exec(name, ["bash", "-lc", command], workspace=WORKSPACE,
                          workdir=workdir or WORKDIR, timeout_seconds=timeout)
        stdout, t1 = _truncate(res.stdout)
        stderr, t2 = _truncate(res.stderr)
        return {"exit_code": res.exit_code, "stdout": stdout, "stderr": stderr, "truncated": t1 or t2}

    def write_file(self, name: str, path: str, content: str) -> dict[str, Any]:
        self._require_ours(name)
        data = content.encode()
        if not path.startswith("/") or "\x00" in path:
            raise ToolError("path must be absolute")
        if len(data) > MAX_WRITE:
            raise ToolError(f"content too large (max {MAX_WRITE} bytes); split it or generate it in the sandbox")
        # path is argv[1], never part of the script text.
        script = 'mkdir -p -- "$(dirname -- "$1")" && cat > "$1"'
        res = self.c.exec(name, ["bash", "-c", script, "write_file", path], workspace=WORKSPACE,
                          stdin=data, timeout_seconds=60)
        if res.exit_code != 0:
            raise ToolError(f"write failed: {_truncate(res.stderr)[0].strip()}")
        return {"path": path, "bytes": len(data)}

    def read_file(self, name: str, path: str, max_bytes: int) -> dict[str, Any]:
        self._require_ours(name)
        if not path.startswith("/") or "\x00" in path:
            raise ToolError("path must be absolute")
        limit = max(1, min(int(max_bytes), MAX_READ))
        res = self.c.exec(name, ["head", "-c", str(limit), "--", path], workspace=WORKSPACE, timeout_seconds=60)
        if res.exit_code != 0:
            raise ToolError(f"read failed: {_truncate(res.stderr)[0].strip()}")
        return {"path": path, "content": res.stdout, "max_bytes": limit}

    def delete(self, name: str) -> dict[str, Any]:
        self._require_ours(name)
        result = self.c.delete(name, workspace=WORKSPACE)
        self.c.wait_deleted(name, workspace=WORKSPACE, expected_sandbox_id=result.sandbox_id, timeout_seconds=120)
        return {"deleted": name}


def build_sandbox_server(backend: SandboxBackend | None = None) -> FastMCP:
    """FastMCP sub-server; gateway.py mounts it under the "sandbox" namespace."""
    # Validate config at startup (fail fast); connect to OpenShell lazily on first use.
    settings = backend.s if backend else Settings()
    _backend: list[SandboxBackend] = [backend] if backend else []

    def get_backend() -> SandboxBackend:
        if not _backend:
            _backend.append(SandboxBackend(settings, client_from_env()))
        return _backend[0]

    async def call(fn_name: str, *args: Any) -> Any:
        try:
            return await anyio.to_thread.run_sync(partial(getattr(get_backend(), fn_name), *args))
        except ToolError:
            raise
        except Exception:
            # Full detail server-side only; the client gets a generic message.
            log.exception("sandbox %s failed", fn_name)
            raise ToolError(f"sandbox {fn_name} failed; see gateway logs") from None

    repos = ", ".join(settings.push_repos) or "(none configured)"
    mcp = FastMCP("sandbox")

    @mcp.tool
    async def create(name_hint: str | None = None) -> dict[str, Any]:
        """Create an isolated Linux sandbox (Ubuntu, git, gh, python3, node).

        Network is default-deny: GitHub (read; push + PRs only for the allowed repos),
        PyPI and npm are reachable. A GitHub token is preconfigured for git and gh; never
        ask the user for one. Sandboxes expire automatically. Returns the sandbox name.
        """
        return await call("create", name_hint)

    @mcp.tool
    async def list() -> list[dict[str, Any]]:  # noqa: A001 - tool name
        """List this gateway's sandboxes with phase and age."""
        return await call("list")

    @mcp.tool
    async def exec(sandbox: str, command: str, workdir: str = WORKDIR, timeout_seconds: int = 120) -> dict[str, Any]:  # noqa: A001
        """Run a bash command in a sandbox and return exit code, stdout and stderr.

        Use for building, testing and git. Clone with https://github.com/<owner>/<repo>.git.
        Push a branch with `git push origin <branch>`; open a PR with
        `gh api -X POST /repos/<owner>/<repo>/pulls -f title=... -f head=<branch> -f base=main`.
        """
        return await call("exec", sandbox, command, workdir, timeout_seconds)

    @mcp.tool
    async def write_file(sandbox: str, path: str, content: str) -> dict[str, Any]:
        """Write a text file (absolute path, up to 1 MiB) inside a sandbox, creating parent dirs."""
        return await call("write_file", sandbox, path, content)

    @mcp.tool
    async def read_file(sandbox: str, path: str, max_bytes: int = 65536) -> dict[str, Any]:
        """Read up to max_bytes (max 256 KiB) of a file inside a sandbox."""
        return await call("read_file", sandbox, path, max_bytes)

    @mcp.tool
    async def delete(sandbox: str) -> dict[str, Any]:
        """Delete a sandbox and everything in it."""
        return await call("delete", sandbox)

    log.info("sandbox tools ready (push repos: %s)", repos)
    return mcp
