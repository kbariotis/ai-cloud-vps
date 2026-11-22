"""Gateway tests. Run inside the built image (make local-test) — no pytest needed.

Covers: single-user enforcement, app config validation, a real stdio backend mounted
through the proxy (needs network for uvx on first run), and the sandbox adapter's
config/policy/safety logic against a fake OpenShell client (the real-OpenShell path is
covered by local/sandbox_e2e.py).
"""

from __future__ import annotations

import asyncio
import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault("ALLOWED_EMAIL", "Me@Example.com")
os.environ.setdefault("GOOGLE_CLIENT_ID", "dummy.apps.googleusercontent.com")
os.environ.setdefault("GOOGLE_CLIENT_SECRET", "dummy-secret")
os.environ.setdefault("BASE_URL", "https://mcp.example.com")
os.environ.setdefault("GATEWAY_JWT_SIGNING_KEY", "x" * 64)
os.environ.setdefault("ALLOWED_CLIENT_REDIRECT_URIS", "https://oauth-redirect.googleusercontent.com/*")
os.environ.setdefault("GATEWAY_APP", "t")
os.environ["UPSTREAM_TEST_TOKEN"] = "upstream-secret"
os.environ.setdefault("SANDBOX_IMAGE", "mcp-sandbox:test")

import gateway  # noqa: E402
from fastmcp import Client  # noqa: E402
from fastmcp.server.auth.auth import AccessToken  # noqa: E402
from fastmcp.server.auth.oauth_proxy import OAuthProxy  # noqa: E402


def app_dir(cfg: dict) -> Path:
    """Temp apps dir containing t.json (GATEWAY_APP=t)."""
    d = Path(tempfile.mkdtemp())
    (d / "t.json").write_text(json.dumps({"mcpServers": cfg}))
    return d


def write_servers(cfg: dict) -> Path:
    p = Path(tempfile.mkstemp(suffix=".json")[1])
    p.write_text(json.dumps({"mcpServers": cfg}))
    return p


def test_config_rejections() -> None:
    bad = {
        "shell command": {"x": {"command": "bash", "args": ["-c", "id"]}},
        "python inline": {"x": {"command": "python", "args": ["-c", "import os"]}},
        "plain http": {"x": {"url": "http://example.com/mcp"}},
        "secret ref": {"x": {"url": "https://a.example", "headers": {"A": "${GOOGLE_CLIENT_SECRET}"}}},
        "mixed refs": {"x": {"url": "https://a.example", "headers": {"A": "${UPSTREAM_TEST_TOKEN}${GATEWAY_JWT_SIGNING_KEY}"}}},
        "bad name": {"../x": {"url": "https://a.example"}},
        "non-string arg": {"x": {"command": "uvx", "args": [1]}},
    }
    for label, cfg in bad.items():
        try:
            gateway.load_servers(write_servers(cfg))
        except gateway.ConfigError:
            continue
        raise AssertionError(f"not rejected: {label}")

    ok = gateway.load_servers(write_servers({"gh": {"url": "https://a.example", "headers": {"Authorization": "Bearer ${UPSTREAM_TEST_TOKEN}"}}}))
    assert ok["gh"]["headers"]["Authorization"] == "Bearer upstream-secret"
    print("PASS  app config validation (7 attacks rejected, UPSTREAM_* expanded)")


def test_insecure_redirect_pattern_rejected() -> None:
    with patch.dict(os.environ, {"ALLOWED_CLIENT_REDIRECT_URIS": "http://evil.example/*"}):
        try:
            gateway.redirect_allowlist()
        except gateway.ConfigError:
            print("PASS  non-https redirect allowlist rejected")
            return
    raise AssertionError("http redirect pattern accepted")


def test_app_selection() -> None:
    for bad in ["../etc/passwd", "github/../x", "", "Github", "nope"]:
        with patch.dict(os.environ, {"GATEWAY_APP": bad}), patch.object(gateway, "APPS_DIR", app_dir({})):
            try:
                gateway.app_servers_file()
            except gateway.ConfigError:
                continue
        raise AssertionError(f"GATEWAY_APP not rejected: {bad!r}")
    with patch.dict(os.environ, {"GATEWAY_APP": "sandbox"}), patch.object(gateway, "APPS_DIR", Path(__file__).with_name("apps")):
        app, path = gateway.app_servers_file()
        assert app == "sandbox" and gateway.load_servers(path) == {} and gateway.load_builtins(path) == ["sandbox"]
    for bad in [{"builtins": "sandbox"}, {"builtins": ["shell"]}, {"builtins": [1]}]:
        p = Path(tempfile.mkstemp(suffix=".json")[1]); p.write_text(json.dumps(bad))
        try:
            gateway.load_builtins(p)
        except gateway.ConfigError:
            continue
        raise AssertionError(f"builtins not rejected: {bad}")
    print("PASS  GATEWAY_APP selection + builtins (traversal/unknown rejected; shipped sandbox.json loads)")


async def test_single_user() -> None:
    with patch.object(gateway, "APPS_DIR", app_dir({})):
        mcp = gateway.build_server()
    cases = {"me@example.com": True, "ME@example.com": True, "attacker@example.com": False, None: False}
    for email, allowed in cases.items():
        async def fake(self, token, _e=email):
            return AccessToken(token="t", client_id="c", scopes=[], claims={"email": _e} if _e else {})

        with patch.object(OAuthProxy, "load_access_token", fake):
            got = await mcp.auth.verify_token("t")  # same entry point as the HTTP middleware
        assert (got is not None) == allowed, f"{email}: expected allowed={allowed}"
    print("PASS  single-user enforcement (owner allowed; other/no email rejected)")


async def test_stdio_backend() -> None:
    with patch.object(gateway, "APPS_DIR", app_dir({"time": {"command": "uvx", "args": ["mcp-server-time==2026.11.11"]}})):
        mcp = gateway.build_server()
    async with Client(mcp) as c:  # in-memory transport: exercises mounting, not HTTP auth
        names = {t.name for t in await c.list_tools()}
        assert {"whoami", "time_get_current_time"} <= names, names
        res = await c.call_tool("time_get_current_time", {"timezone": "Europe/Athens"})
        assert "Europe/Athens" in res.content[0].text
    print(f"PASS  stdio backend mounted and callable ({sorted(names)})")


def test_sandbox_config_and_policy() -> None:
    import openshell_common as oc

    for bad in ["a/b;id", "../x", "owner", "o/r/extra", "-bad/repo", "o/$(id)"]:
        try:
            oc.parse_push_repos(bad)
        except oc.OpenShellConfigError:
            continue
        raise AssertionError(f"repo not rejected: {bad!r}")
    assert oc.parse_push_repos(" me/app , me/app,me/lib ") == ["me/app", "me/lib"]

    pol = oc.build_policy(["me/app"])
    rules = pol.network_policies
    reg = rules["package_registries"]
    assert {e.host for e in reg.endpoints} == set(oc.REGISTRY_HOSTS)
    assert {b.path for b in reg.binaries} == set(oc.REGISTRY_BINARIES)
    git = rules["repo_0_git"]
    paths = {(r.allow.method, r.allow.path) for e in git.endpoints for r in e.rules}
    assert ("POST", "/me/app.git/git-receive-pack") in paths and ("POST", "/me/app/git-receive-pack") in paths
    assert all("/me/app" in p for _, p in paths), paths  # push rules never reach other repos
    assert [b.path for b in git.binaries] == ["/usr/bin/git"]
    api = rules["repo_0_api"]
    assert {(r.allow.method, r.allow.path) for e in api.endpoints for r in e.rules} == {
        ("POST", "/repos/me/app/pulls"), ("PATCH", "/repos/me/app/pulls/*"), ("POST", "/repos/me/app/issues/*/comments")}
    assert set(oc.build_policy([]).network_policies) == {"package_registries"}  # no repos => no write rules

    prof = oc.load_github_profile()
    assert prof.id == "github" and {b.path for b in prof.binaries} == {"/usr/bin/gh", "/usr/bin/git"}
    print("PASS  sandbox config + policy (bad repos rejected; writes scoped to allowlisted repos; profile loads)")


class _Ref:
    def __init__(self, name, labels):
        self.name, self.labels, self.status = name, labels, None


class _Exec:
    def __init__(self, code=0, out="", err=""):
        self.exit_code, self.stdout, self.stderr = code, out, err


class FakeOpenShell:
    """Records calls; just enough of SandboxClient for SandboxBackend."""

    def __init__(self, refs):
        self.refs = {r.name: r for r in refs}
        self.calls = []

    def list_all(self, workspace, label_selector=None):
        k, v = label_selector.split("=")
        return [r for r in self.refs.values() if r.labels.get(k) == v]

    def get(self, name, workspace):
        if name not in self.refs:
            import grpc
            from openshell import GatewayError

            class _E(grpc.RpcError):
                def code(self):
                    return grpc.StatusCode.NOT_FOUND

                def details(self):
                    return "not found"

            raise GatewayError(_E())
        return self.refs[name]

    def exec(self, name, cmd, **kw):
        self.calls.append(("exec", name, cmd, kw))
        return _Exec(out="A" * 200_000)

    def delete(self, name, workspace, allow_missing=False):
        self.calls.append(("delete", name))
        self.refs.pop(name, None)

        class R:
            sandbox_id = "id"
        return R()

    def create(self, **kw):
        self.calls.append(("create", kw))

    def wait_ready(self, *a, **k):
        pass

    def wait_deleted(self, *a, **k):
        pass


def test_sandbox_backend_safety() -> None:
    import time

    import sandbox_tools as st
    from fastmcp.exceptions import ToolError

    now = int(time.time())
    ours = {st.OWNER_LABEL: st.OWNER_VALUE, st.CREATED_LABEL: str(now)}
    fake = FakeOpenShell([_Ref("mine-1", ours), _Ref("foreign", {"managed-by": "someone-else"}),
                          _Ref("old-1", {**ours, st.CREATED_LABEL: str(now - 10 * 86400)})])
    with patch.dict(os.environ, {"SANDBOX_PUSH_REPOS": "me/app", "SANDBOX_MAX": "2"}):
        b = st.SandboxBackend(st.Settings(), fake)

    def rejects(fn, *args, msg):
        try:
            fn(*args)
        except ToolError as exc:
            assert msg in str(exc), str(exc)
            return
        raise AssertionError(f"{fn.__name__}{args} not rejected")

    rejects(b.exec, "foreign", "id", "/sandbox", 10, msg="no sandbox named")      # foreign sandbox hidden
    rejects(b.exec, "missing", "id", "/sandbox", 10, msg="no sandbox named")
    rejects(b.exec, "../x", "id", "/sandbox", 10, msg="invalid sandbox name")
    rejects(b.write_file, "mine-1", "relative.txt", "x", msg="absolute")
    rejects(b.write_file, "mine-1", "/a", "x" * (st.MAX_WRITE + 1), msg="too large")

    out = b.exec("mine-1", "echo hi", "/sandbox", 99999)
    _, _, cmd, kw = fake.calls[-1]
    assert cmd == ["bash", "-lc", "echo hi"] and kw["timeout_seconds"] == st.MAX_TIMEOUT
    assert out["truncated"] and len(out["stdout"].encode()) <= st.MAX_OUTPUT + 32

    b.write_file("mine-1", "/sandbox/$(id).txt", "data")
    _, _, cmd, kw = fake.calls[-1]
    assert cmd[-1] == "/sandbox/$(id).txt" and "$(id)" not in cmd[2] and kw["stdin"] == b"data"  # argv, not script

    created = b.create("My Box!")  # reaps old-1 (expired), then fits under SANDBOX_MAX=2
    assert ("delete", "old-1") in fake.calls and created["sandbox"].startswith("my-box-")
    spec = [c for c in fake.calls if c[0] == "create"][-1][1]["spec"]
    assert list(spec.providers) == ["github"] and spec.template.image == "mcp-sandbox:test"
    assert "repo_0_git" in spec.policy.network_policies
    fake.refs[created["sandbox"]] = _Ref(created["sandbox"], ours)
    rejects(b.create, None, msg="sandbox limit reached")
    print("PASS  sandbox backend safety (ownership, names, sizes, timeout clamp, argv paths, TTL reap, limit)")


if __name__ == "__main__":
    test_config_rejections()
    test_insecure_redirect_pattern_rejected()
    test_app_selection()
    asyncio.run(test_single_user())
    asyncio.run(test_stdio_backend())
    test_sandbox_config_and_policy()
    test_sandbox_backend_safety()
    print("ALL GATEWAY TESTS PASSED")
