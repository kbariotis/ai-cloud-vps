"""One-shot OpenShell bootstrap (runs as the `openshell-setup` compose service on every deploy).

Idempotent:
  1. wait for the OpenShell gateway
  2. import / update the GitHub provider profile (openshell/github-profile.yaml)
  3. create / update the `github` provider from GITHUB_TOKEN (rotation = redeploy)

This is the only process that ever sees the PAT. The internet-facing gateway (gw-sandbox)
references the provider by name and never holds the token.
"""

from __future__ import annotations

import logging
import os
import sys
import time

import grpc
from openshell import GatewayError
from openshell._proto import datamodel_pb2 as dm
from openshell._proto import openshell_pb2 as pb

from openshell_common import (
    GITHUB_PROVIDER,
    WORKSPACE,
    OpenShellConfigError,
    client_from_env,
    load_github_profile,
    status_of,
)

log = logging.getLogger("openshell-setup")
SEL = dm.WorkspaceSelector(workspace=WORKSPACE)


def wait_for_gateway(client, attempts: int = 60) -> None:
    for i in range(attempts):
        try:
            log.info("OpenShell gateway %s is up", client.health().version)
            return
        except Exception:  # noqa: BLE001 - startup race; retried
            time.sleep(2)
    raise SystemExit("OpenShell gateway did not become ready")


def ensure_profile(stub) -> None:
    profile = load_github_profile()
    item = pb.ProviderProfileImportItem(profile=profile, source="mcp-vps")
    try:
        existing = stub.GetProviderProfile(pb.GetProviderProfileRequest(workspace_scope=SEL, id=profile.id), timeout=30)
    except GatewayError as exc:
        if status_of(exc) != grpc.StatusCode.NOT_FOUND:
            raise
        stub.ImportProviderProfiles(pb.ImportProviderProfilesRequest(workspace_scope=SEL, profiles=[item]), timeout=30)
        log.info("imported provider profile %s", profile.id)
        return
    current = existing.profile if hasattr(existing, "profile") else existing
    stub.UpdateProviderProfiles(pb.UpdateProviderProfilesRequest(
        workspace_scope=SEL, id=profile.id, profile=item,
        expected_resource_version=getattr(current, "resource_version", 0)), timeout=30)
    log.info("updated provider profile %s", profile.id)


def ensure_provider(stub, token: str) -> None:
    provider = dm.Provider(metadata=dm.ObjectMeta(name=GITHUB_PROVIDER), type="github",
                           profile_workspace=WORKSPACE, credentials={"GITHUB_TOKEN": token})
    try:
        stub.CreateProvider(pb.CreateProviderRequest(workspace_scope=SEL, provider=provider), timeout=30)
        log.info("created provider %s", GITHUB_PROVIDER)
    except GatewayError as exc:
        if status_of(exc) != grpc.StatusCode.ALREADY_EXISTS:
            raise
        stub.UpdateProvider(pb.UpdateProviderRequest(workspace_scope=SEL, provider=provider), timeout=30)
        log.info("updated provider %s (credential rotated)", GITHUB_PROVIDER)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    try:
        client = client_from_env()
    except OpenShellConfigError as exc:
        log.error("config error: %s", exc)
        sys.exit(2)
    with client:
        wait_for_gateway(client)
        stub = client._stub  # SDK exposes the generated stub; there's no wrapper for these RPCs
        ensure_profile(stub)
        if token:
            ensure_provider(stub, token)
        else:
            log.warning("GITHUB_TOKEN is empty: sandboxes will have no GitHub credential")
    log.info("OpenShell setup complete")


if __name__ == "__main__":
    main()
