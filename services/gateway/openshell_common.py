"""Shared OpenShell helpers: gateway client, provider profile and sandbox policy builders.

Everything here is driven by deploy-time config (env vars, files in the image); nothing
is taken from MCP requests. Verified against OpenShell 0.1.8 (gateway + SDK pinned).
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import grpc
import yaml
from google.protobuf import json_format
from openshell import SandboxClient, TlsConfig
from openshell._proto import openshell_pb2 as pb
from openshell._proto import sandbox_pb2 as sb

WORKSPACE = "default"
GITHUB_PROVIDER = "github"
PROFILE_FILE = Path(__file__).with_name("openshell") / "github-profile.yaml"

# owner/repo, GitHub's allowed characters.
REPO_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9._-]{1,100}$")

_ACCESS = {
    "read-only": "NETWORK_ACCESS_PRESET_READ_ONLY",
    "read-write": "NETWORK_ACCESS_PRESET_READ_WRITE",
    "full": "NETWORK_ACCESS_PRESET_FULL",
}
_ENFORCE = {"enforce": "NETWORK_ENFORCEMENT_MODE_ENFORCE", "audit": "NETWORK_ENFORCEMENT_MODE_AUDIT"}
_ENF = _ENFORCE["enforce"]
_RO = _ACCESS["read-only"]

# Processes allowed to use the package-registry rule (verified: pip via python3, npm via node).
REGISTRY_BINARIES = ["/usr/bin/python3", "/usr/bin/python3.12", "/usr/bin/node", "/usr/bin/npm"]
REGISTRY_HOSTS = ["pypi.org", "files.pythonhosted.org", "registry.npmjs.org"]


class OpenShellConfigError(ValueError):
    pass


def status_of(exc: BaseException) -> grpc.StatusCode | None:
    """gRPC status of an SDK error (GatewayError is a grpc.RpcError; code() is a method)."""
    code = getattr(exc, "code", None)
    try:
        value = code() if callable(code) else code
    except Exception:  # noqa: BLE001 - not an RPC error
        return None
    return value if isinstance(value, grpc.StatusCode) else None


def client_from_env() -> SandboxClient:
    """mTLS client for the OpenShell gateway (endpoint + cert dir come from env)."""
    endpoint = os.environ.get("OPENSHELL_ENDPOINT", "").strip()
    tls_dir = Path(os.environ.get("OPENSHELL_TLS_DIR", "/openshell-client"))
    if not endpoint:
        raise OpenShellConfigError("missing OPENSHELL_ENDPOINT")
    paths = {"ca": tls_dir / "ca.crt", "cert": tls_dir / "tls.crt", "key": tls_dir / "tls.key"}
    missing = [n for n, p in paths.items() if not p.is_file()]
    if missing:
        raise OpenShellConfigError(f"missing OpenShell client TLS files: {missing}")
    tls = TlsConfig(ca_path=paths["ca"], cert_path=paths["cert"], key_path=paths["key"])
    return SandboxClient(endpoint, tls=tls, timeout=60)


def parse_push_repos(raw: str) -> list[str]:
    repos = [r.strip() for r in raw.split(",") if r.strip()]
    bad = [r for r in repos if not REPO_RE.fullmatch(r)]
    if bad:
        raise OpenShellConfigError(f"invalid repo(s) in SANDBOX_PUSH_REPOS: {bad}")
    return sorted(set(repos))


def _endpoint(e: dict[str, Any]) -> dict[str, Any]:
    e = dict(e)
    if "access" in e:
        e["access"] = _ACCESS[e["access"]]
    if "enforcement" in e:
        e["enforcement"] = _ENFORCE[e["enforcement"]]
    return e


def load_github_profile(path: Path = PROFILE_FILE) -> pb.ProviderProfile:
    """Provider profile YAML (upstream format) -> protobuf."""
    doc = yaml.safe_load(path.read_text())
    doc["endpoints"] = [_endpoint(e) for e in doc.get("endpoints", [])]
    doc["binaries"] = [{"path": b} if isinstance(b, str) else b for b in doc.get("binaries", [])]
    category = doc.pop("category", None)
    profile = json_format.ParseDict(doc, pb.ProviderProfile())
    if category:
        enum = pb.ProviderProfile.DESCRIPTOR.fields_by_name["category"].enum_type
        matches = [v.number for v in enum.values if v.name.lower().endswith(category.lower())]
        if not matches:
            raise OpenShellConfigError(f"unknown profile category {category!r}")
        profile.category = matches[0]
    return profile


def _repo_rules(repo: str) -> list[dict[str, Any]]:
    git_paths = []
    for base in (f"/{repo}.git", f"/{repo}"):  # remotes may or may not end in .git
        git_paths += [
            {"allow": {"method": "GET", "path": f"{base}/info/refs*"}},
            {"allow": {"method": "POST", "path": f"{base}/git-upload-pack"}},
            {"allow": {"method": "POST", "path": f"{base}/git-receive-pack"}},
        ]
    return git_paths


def build_policy(push_repos: list[str]) -> sb.SandboxPolicy:
    """Network policy for every sandbox.

    Default-deny. On top of the GitHub provider's read-only access:
      - package registries, read-only, for python/node only
      - per allowlisted repo: git push (git only) and opening/updating PRs via REST (gh only)
    """
    policies: dict[str, Any] = {
        "package_registries": {
            "name": "package-registries",
            "endpoints": [
                {"host": h, "port": 443, "protocol": "rest", "access": _RO, "enforcement": _ENF}
                for h in REGISTRY_HOSTS
            ],
            "binaries": [{"path": p} for p in REGISTRY_BINARIES],
        }
    }
    for i, repo in enumerate(push_repos):
        policies[f"repo_{i}_git"] = {
            "name": f"git-push-{i}",
            "endpoints": [{"host": "github.com", "port": 443, "protocol": "rest", "enforcement": _ENF,
                           "rules": _repo_rules(repo)}],
            "binaries": [{"path": "/usr/bin/git"}],
        }
        api = f"/repos/{repo}"
        policies[f"repo_{i}_api"] = {
            "name": f"github-prs-{i}",
            "endpoints": [{"host": "api.github.com", "port": 443, "protocol": "rest", "enforcement": _ENF,
                           "rules": [
                               {"allow": {"method": "POST", "path": f"{api}/pulls"}},
                               {"allow": {"method": "PATCH", "path": f"{api}/pulls/*"}},
                               {"allow": {"method": "POST", "path": f"{api}/issues/*/comments"}},
                           ]}],
            "binaries": [{"path": "/usr/bin/gh"}],
        }
    return json_format.ParseDict({"version": 1, "network_policies": policies}, sb.SandboxPolicy())
