"""End-to-end check of the sandbox MCP tools against a real (local) OpenShell gateway.

Runs INSIDE gw-sandbox (make local-sandbox-e2e) using FastMCP's in-memory client, so it
exercises the real tool code, real mTLS to OpenShell and real sandboxes; only the OAuth
layer is skipped (local-smoke covers that).
"""

import asyncio
import json
import sys

from fastmcp import Client

from sandbox_tools import build_sandbox_server

results: list[tuple[str, bool, str]] = []


def check(label: str, ok: bool, detail: str = "") -> None:
    results.append((label, ok, detail))
    print(f"{'PASS' if ok else 'FAIL'}  {label}" + (f"  ({detail})" if detail and not ok else ""))


def data(res):
    if res.structured_content is not None:
        sc = res.structured_content
        return sc.get("result", sc) if isinstance(sc, dict) and set(sc) == {"result"} else sc
    return json.loads(res.content[0].text)


async def main() -> None:
    async with Client(build_sandbox_server()) as c:
        names = {t.name for t in await c.list_tools()}
        check("tools exposed", {"create", "list", "exec", "write_file", "read_file", "delete"} <= names, str(names))

        # Long, Gemini-style hint: OpenShell caps names at 19 chars (a 25-char name failed live)
        box = data(await c.call_tool("create", {"name_hint": "e2e my-website.example feature"}))
        sb = box["sandbox"]
        check("create (long name hint)", sb.startswith("e2e-my-websi") and len(sb) <= 19, str(box))

        async def run(cmd: str, **kw):
            return data(await c.call_tool("exec", {"sandbox": sb, "command": cmd, **kw}))

        r = await run("id -un; uname -m")
        check("exec as unprivileged user", r["exit_code"] == 0 and r["stdout"].startswith("ubuntu"), str(r))

        await c.call_tool("write_file", {"sandbox": sb, "path": "/sandbox/app/main.py",
                                          "content": "import six\nprint('ok', six.__version__)\n"})
        r = await run("python3 -m venv .v && .v/bin/pip install -q six==1.16.0 && .v/bin/python main.py",
                      workdir="/sandbox/app", timeout_seconds=300)
        check("write_file + pip install + run tests", r["exit_code"] == 0 and "ok 1.16.0" in r["stdout"], str(r))

        rf = data(await c.call_tool("read_file", {"sandbox": sb, "path": "/sandbox/app/main.py"}))
        check("read_file", "import six" in rf["content"], str(rf))

        evil = "/sandbox/x/$(touch /sandbox/PWNED).txt"
        await c.call_tool("write_file", {"sandbox": sb, "path": evil, "content": "x"})
        r = await run("ls /sandbox/PWNED 2>/dev/null && echo INJECTED || echo safe; ls /sandbox/x")
        check("write_file path is not shell-evaluated", "safe" in r["stdout"] and "$(touch" in r["stdout"], str(r))

        r = await run("git clone -q --depth 1 https://github.com/octocat/Hello-World.git /sandbox/hw && ls /sandbox/hw",
                      timeout_seconds=120)
        check("git clone via GitHub provider", r["exit_code"] == 0 and "README" in r["stdout"], str(r))

        r = await run('case "$GITHUB_TOKEN" in openshell:resolve:*) echo placeholder;; "") echo empty;; *) echo REAL;; esac')
        check("agent sees only a token placeholder", r["stdout"].strip() == "placeholder", str(r))

        r = await run("curl -sS -m 8 -o /dev/null -w '%{http_code}' https://example.com; echo")
        check("egress to non-allowed host blocked", "000" in r["stdout"], str(r))

        r = await run("gh api -X POST /repos/octocat/Hello-World/issues -f title=t 2>&1 | head -c 300")
        check("GitHub write outside allowlist denied by policy", "policy_denied" in r["stdout"], str(r))

        if box["push_repos"]:
            repo = box["push_repos"][0]
            r = await run(f"gh api -X POST /repos/{repo}/pulls -f title=t -f head=x -f base=main 2>&1 | head -c 300")
            # Allowed by policy => the request reaches GitHub (which rejects the fake token).
            check(f"PR creation on allowlisted {repo} passes the policy",
                  "policy_denied" not in r["stdout"] and ("401" in r["stdout"] or "Bad credentials" in r["stdout"]), str(r))
            r = await run(f"gh api -X POST /repos/{repo}/issues -f title=t 2>&1 | head -c 300")
            check(f"non-PR write on allowlisted {repo} still denied", "policy_denied" in r["stdout"], str(r))

        lst = data(await c.call_tool("list", {}))
        check("list shows the sandbox", any(x["sandbox"] == sb for x in lst), str(lst))

        try:
            await c.call_tool("exec", {"sandbox": "not-ours-xyz", "command": "true"})
            check("unknown sandbox rejected", False, "no error")
        except Exception as exc:  # noqa: BLE001
            check("unknown sandbox rejected", "no sandbox named" in str(exc), str(exc))

        try:
            await c.call_tool("exec", {"sandbox": "../etc", "command": "true"})
            check("bad sandbox name rejected", False, "no error")
        except Exception as exc:  # noqa: BLE001
            check("bad sandbox name rejected", "invalid sandbox name" in str(exc), str(exc))

        d = data(await c.call_tool("delete", {"sandbox": sb}))
        check("delete", d.get("deleted") == sb, str(d))

    failed = [r for r in results if not r[1]]
    print(f"---- {len(results) - len(failed)} passed, {len(failed)} failed")
    sys.exit(1 if failed else 0)


asyncio.run(main())
