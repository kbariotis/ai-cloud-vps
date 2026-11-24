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


async def test_registration_logging() -> None:
    import logging
    from mcp.shared.auth import OAuthClientInformationFull

    with patch.object(gateway, "APPS_DIR", app_dir({})):
        mcp = gateway.build_server()

    records: list[str] = []
    handler = logging.Handler()
    handler.emit = lambda r: records.append(r.getMessage())  # type: ignore[method-assign]
    gateway.log.addHandler(handler)
    level = gateway.log.level
    gateway.log.setLevel(logging.INFO)  # main() configures logging; tests don't run main()
    try:
        def info(uri: str) -> OAuthClientInformationFull:
            return OAuthClientInformationFull(
                client_id="c1", redirect_uris=[uri], token_endpoint_auth_method="none",
                grant_types=["authorization_code"], response_types=["code"])

        good = "https://oauth-redirect.googleusercontent.com/r/user_bound_custom-mcp-1-mcp_example_com"
        await mcp.auth.register_client(info(good))  # Gemini's shape is accepted
        assert any("client registered" in m and good in m for m in records), records

        bad = "https://evil.example/cb?\nFAKE log line"
        try:
            await mcp.auth.register_client(info(bad))
        except Exception:
            pass
        else:
            raise AssertionError("disallowed redirect URI was registered")
        refused = [m for m in records if "registration refused" in m]
        assert refused and "evil.example" in refused[0] and "\n" not in refused[0], refused  # logged, escaped

        assert await mcp.auth.get_client("nope") is None
        assert any("unknown OAuth client_id 'nope'" in m for m in records), records

        # Flood: unauthenticated callers can't push unbounded lines into the log
        records.clear()
        mcp.auth._log_budget = gateway.LogBudget(limit=3, window=60)
        for i in range(10):
            await mcp.auth.get_client(f"junk-{i}")
        assert sum("unknown OAuth client_id" in m for m in records) == 3, records
        mcp.auth._log_budget.start -= 61  # window elapsed: the next event reports the drop count
        await mcp.auth.get_client("junk-last")
        assert any("suppressed 7 OAuth client log lines" in m for m in records), records
    finally:
        gateway.log.removeHandler(handler)
        gateway.log.setLevel(level)
    print("PASS  registration logging (accepted/refused redirect URIs, unknown client ids; log-injection safe; flood-capped)")


def test_access_log_redaction() -> None:
    import logging

    # Same shape uvicorn.access emits: (client, method, full_path, http_version, status)
    rec = logging.LogRecord("uvicorn.access", logging.INFO, __file__, 1, '%s - "%s %s HTTP/%s" %d',
                            ("1.2.3.4:5", "GET", "/auth/callback?code=4/SECRETCODE&state=abc", "1.1", 302), None)
    assert gateway.RedactQuery().filter(rec)
    msg = rec.getMessage()
    assert "SECRETCODE" not in msg and "state=" not in msg and "/auth/callback?<redacted>" in msg, msg
    plain = logging.LogRecord("uvicorn.access", logging.INFO, __file__, 1, '%s - "%s %s HTTP/%s" %d',
                              ("1.2.3.4:5", "POST", "/mcp", "1.1", 401), None)
    gateway.RedactQuery().filter(plain)
    assert '"POST /mcp HTTP/1.1" 401' in plain.getMessage()
    print("PASS  access log redaction (OAuth query strings dropped, plain paths kept)")


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


def _gateway_error(code_name: str, details: str):
    import grpc
    from openshell import GatewayError

    class _E(grpc.RpcError):
        def code(self):
            return getattr(grpc.StatusCode, code_name)

        def details(self):
            return details

    return GatewayError(_E())


async def test_sandbox_error_messages() -> None:
    import sandbox_tools as st
    from fastmcp.exceptions import ToolError

    msg = st.client_message
    # Fixable by the caller: OpenShell's reason reaches the agent
    assert msg("create", _gateway_error("INVALID_ARGUMENT", "name exceeds maximum length (25 > 19)")) == \
        "sandbox create rejected (invalid_argument): name exceeds maximum length (25 > 19)"
    # Not fixable / internal: generic, internals (addresses, TLS) stay in the server log
    for code, detail in [("UNAVAILABLE", "failed to connect to 10.0.0.5:8080: tls handshake"),
                         ("INTERNAL", "panic at src/driver.rs:42"), ("PERMISSION_DENIED", "client cert CN=x")]:
        assert msg("exec", _gateway_error(code, detail)) == "sandbox exec failed; see gateway logs", code
    assert msg("exec", ValueError("boom /etc/secret")) == "sandbox exec failed; see gateway logs"
    assert msg("exec", _gateway_error("INVALID_ARGUMENT", "")) == "sandbox exec failed; see gateway logs"
    # Reason is one line and bounded, so it can't smuggle structure into the agent's context
    m = msg("create", _gateway_error("INVALID_ARGUMENT", "bad\nname\r\n" + "x" * 1000))
    assert "\n" not in m and "\r" not in m and len(m) < 300, m

    # End to end through the MCP tool, as Gemini sees it
    class RejectingCreate(FakeOpenShell):
        def create(self, **kw):
            raise _gateway_error("INVALID_ARGUMENT", "name exceeds maximum length (25 > 19)")

    with patch.dict(os.environ, {"SANDBOX_PUSH_REPOS": "me/app"}):
        backend = st.SandboxBackend(st.Settings(), RejectingCreate([]))
    async with Client(st.build_sandbox_server(backend)) as c:
        try:
            await c.call_tool("create", {"name_hint": "x"})
        except ToolError as exc:
            assert "name exceeds maximum length" in str(exc), str(exc)
        else:
            raise AssertionError("create should have failed")
    print("PASS  sandbox error messages (fixable reasons surfaced; internals generic; one line, bounded)")


async def test_tool_metadata() -> None:
    import time

    import sandbox_tools as st
    from fastmcp.exceptions import ToolError

    ours = {st.OWNER_LABEL: st.OWNER_VALUE, st.CREATED_LABEL: str(int(time.time()))}
    with patch.dict(os.environ, {"SANDBOX_PUSH_REPOS": "me/app"}):
        backend = st.SandboxBackend(st.Settings(), FakeOpenShell([_Ref("mine-1", ours)]))
    async with Client(st.build_sandbox_server(backend)) as c:
        tools = {t.name: t for t in await c.list_tools()}
        # What the approval card can show: a title, honest hints, and the agent's stated purpose
        assert tools["exec"].title == "Run shell command in sandbox"
        assert tools["exec"].annotations.destructive_hint is True and tools["exec"].annotations.open_world_hint is True
        assert tools["list"].annotations.read_only_hint is True and tools["read_file"].annotations.read_only_hint is True
        assert tools["delete"].annotations.destructive_hint is True
        for name in ("exec", "write_file"):
            schema = tools[name].input_schema
            assert "purpose" in schema["required"] and next(iter(schema["properties"])) == "purpose", schema

        for bad in ["", "   ", "x" * (st.MAX_PURPOSE + 1)]:
            try:
                await c.call_tool("exec", {"purpose": bad, "sandbox": "mine-1", "command": "true"})
            except ToolError as exc:
                assert "purpose" in str(exc), str(exc)
            else:
                raise AssertionError(f"purpose {bad[:10]!r} accepted")
        # Multi-line purposes are collapsed to one line, not rejected
        await c.call_tool("exec", {"purpose": "Run\ntests", "sandbox": "mine-1", "command": "true"})
    print("PASS  tool metadata (titles, hints, required one-line purpose on exec/write_file)")


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

    # Names always fit OpenShell's limit and the ownership regex, whatever the hint
    for hint in ["my-long-website.example feature branch", "a" * 200, "abcdefghijk-------xyz", "!!!", None, "Ünïcødé"]:
        n = st._slug(hint)
        assert len(n) <= st.MAX_NAME and st.NAME_RE.fullmatch(n) and "--" not in n, (hint, n)
    assert st._slug("my-long-website.example feature").startswith("my-long-webs")

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
    asyncio.run(test_registration_logging())
    test_access_log_redaction()
    asyncio.run(test_stdio_backend())
    test_sandbox_config_and_policy()
    test_sandbox_backend_safety()
    asyncio.run(test_sandbox_error_messages())
    asyncio.run(test_tool_metadata())
    print("ALL GATEWAY TESTS PASSED")
