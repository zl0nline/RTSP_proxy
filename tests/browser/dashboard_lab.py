from __future__ import annotations

import argparse
import html
import secrets
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlencode
from uuid import UUID, uuid4

import uvicorn
from fastapi import Request
from fastapi.responses import HTMLResponse, RedirectResponse

from rtsp_proxy.access import (
    AccessGrant,
    AccessGrantControl,
    AccessGrantIdempotency,
    AccessGrantIssueReplayed,
    AccessGrantSummary,
    AccessPolicy,
    AccessPolicyControl,
    PepperVerifier,
)
from rtsp_proxy.app import create_app
from rtsp_proxy.config import RuntimeRole, Settings
from rtsp_proxy.identifiers import PublicId
from rtsp_proxy.media import MediaPathConfig, MediaPathInventory
from rtsp_proxy.nodes import (
    CameraControl,
    InMemoryNodeStore,
    MediaNode,
    NodeControl,
    NodeHealth,
    NodeState,
)
from rtsp_proxy.observability import (
    FleetSnapshot,
    InMemoryObservabilityStore,
    NodeMetricSample,
    NodeScrapeStatus,
    NodeSnapshot,
)
from rtsp_proxy.operator_access import (
    InMemoryOperatorSessionStore,
    OperatorAccount,
    OperatorIdentitySource,
    OperatorRole,
    OperatorSessionControl,
)
from rtsp_proxy.operator_identity import (
    InMemoryOidcFlowStore,
    OidcIdentity,
    OidcLoginControl,
    OidcProvider,
)
from rtsp_proxy.reconcile import CameraMutationControl, ConfirmationTokenService

ACCOUNT_ID = UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
NODE_ID = UUID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
CAMERA_ID = UUID("cccccccc-cccc-4ccc-8ccc-cccccccccccc")
CREATED_CAMERA_ID = UUID("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee")
SOURCE_SECRET_CANARY = "rtsp://source-secret-canary.invalid/private"
DOWNSTREAM_SECRET_CANARY = "browser-downstream-secret-canary-0123456789abcdef"


class _LabAccessStore:
    def __init__(self) -> None:
        self.policy = AccessPolicy(camera_id=CAMERA_ID, revision=1)
        self.grants: dict[UUID, AccessGrant] = {}
        self.requests: set[tuple[UUID, UUID]] = set()

    def get_access_policy(self, camera_id: UUID) -> AccessPolicy | None:
        return self.policy if camera_id == CAMERA_ID else None

    def set_access_policy(
        self,
        policy: AccessPolicy,
        *,
        expected_revision: int,
        mutation_context: object | None = None,
    ) -> AccessPolicy:
        del mutation_context
        if policy.camera_id != CAMERA_ID or self.policy.revision != expected_revision:
            raise ValueError("lab_access_policy_conflict")
        self.policy = policy
        return policy

    def list_access_grants(
        self,
        camera_id: UUID,
        *,
        limit: int,
    ) -> tuple[AccessGrantSummary, ...]:
        if camera_id != CAMERA_ID:
            return ()
        return tuple(
            AccessGrantSummary.from_grant(grant)
            for grant in tuple(self.grants.values())[:limit]
        )

    def get_access_grant_by_id(self, grant_id: UUID) -> AccessGrant | None:
        return self.grants.get(grant_id)

    def create_access_grant(
        self,
        grant: AccessGrant,
        *,
        mutation_context: object | None = None,
        idempotency: AccessGrantIdempotency | None = None,
    ) -> AccessGrant:
        del mutation_context
        if idempotency is not None:
            key = (idempotency.actor_session_id, idempotency.key)
            if key in self.requests:
                raise AccessGrantIssueReplayed("access_grant_issue_replayed")
            self.requests.add(key)
        self.grants[grant.id] = grant
        return grant

    def check_access_grant_request(self, request: AccessGrantIdempotency) -> None:
        del request


class _LabTokenEndpoint:
    def exchange(self, *, code: str, code_verifier: str) -> str:
        if code != "browser-e2e-code" or len(code_verifier) != 43:
            raise ValueError("lab_oidc_exchange_invalid")
        return "browser-e2e-id-token"


class _LabClaimsVerifier:
    def verify(self, *, id_token: str, nonce: str) -> OidcIdentity:
        if id_token != "browser-e2e-id-token" or len(nonce) != 43:
            raise ValueError("lab_oidc_claims_invalid")
        return OidcIdentity(
            subject="browser-e2e-operator",
            display_name="Browser E2E operator",
            groups=frozenset({"rtsp-operators"}),
            roles=frozenset({OperatorRole.ADMIN}),
            mfa_verified=True,
        )


class _LabMediaNode:
    def __init__(self, *, public_id: PublicId, source_url: str) -> None:
        self._paths = {
            public_id: MediaPathConfig(name=public_id, source_url=source_url)
        }
        self._runtime: dict[PublicId, tuple[bool, int] | None] = {
            public_id: (True, 1)
        }

    def put_path(self, path: MediaPathConfig) -> None:
        self._paths[path.name] = path
        if path.max_readers == -1:
            self._runtime[path.name] = (False, 0)

    def get_path(self, name: PublicId) -> MediaPathConfig | None:
        return self._paths.get(name)

    def inventory_paths(self) -> MediaPathInventory:
        return MediaPathInventory(
            camera_ids=tuple(sorted(self._paths, key=str)),
            no_oracle_matcher_present=True,
        )

    def delete_path(self, name: PublicId) -> None:
        self._paths.pop(name, None)
        self._runtime.pop(name, None)

    def path_runtime_status(self, name: PublicId) -> tuple[bool, int] | None:
        return self._runtime.get(name)


class _LabMediaNodes:
    def __init__(self, client: _LabMediaNode) -> None:
        self._client = client

    def for_node(self, node: MediaNode) -> _LabMediaNode:
        if node.id != NODE_ID:
            raise ValueError("lab_media_node_invalid")
        return self._client


def build_lab_app(*, origin: str) -> Any:
    now = datetime.now(UTC)
    node = MediaNode(
        id=NODE_ID,
        name="edge-browser-lab",
        external_port=10543,
        state=NodeState.RUNNING,
        runtime_state=NodeState.RUNNING,
        health=NodeHealth.HEALTHY,
        management_fresh=True,
        management_observed_at=now,
        config_compatible=True,
        desired_revision=1,
        applied_revision=1,
    )
    node_store = InMemoryNodeStore(nodes=(node,))
    camera_ids = iter((CAMERA_ID, CREATED_CAMERA_ID))
    public_ids = iter(("a" * 26, "b" * 25 + "e"))
    cameras = CameraControl(
        store=node_store,
        new_camera_id=camera_ids.__next__,
        new_public_id=public_ids.__next__,
    )
    camera = cameras.create_camera(
        name="Front entrance",
        source_url=SOURCE_SECRET_CANARY,
        node_id=NODE_ID,
    )
    nodes = NodeControl(
        store=node_store,
        choose_port=lambda available: available[0],
        new_node_id=lambda: UUID("dddddddd-dddd-4ddd-8ddd-dddddddddddd"),
        is_port_bindable=lambda _port: True,
    )
    mutations = CameraMutationControl(
        store=node_store,
        media_nodes=_LabMediaNodes(
            _LabMediaNode(public_id=camera.public_id, source_url=camera.source_url)
        ),
        confirmations=ConfirmationTokenService(
            secret=b"browser-e2e-confirmation-secret-at-least-32-bytes",
            lifetime_seconds=30,
        ),
    )
    observations = InMemoryObservabilityStore()
    observations.save_snapshot(
        FleetSnapshot(
            generated_at=now,
            configured_nodes=1,
            max_nodes=50,
            registered_cameras=1,
            external_ports_used=1,
            external_ports_free=999,
            nodes=(
                NodeSnapshot(
                    node_id=NODE_ID,
                    name=node.name,
                    external_port=node.external_port,
                    desired_state=NodeState.RUNNING,
                    runtime_state=NodeState.RUNNING,
                    health=NodeHealth.HEALTHY,
                    registered_cameras=1,
                    camera_capacity=100,
                    desired_revision=1,
                    applied_revision=1,
                    scrape_status=NodeScrapeStatus.FRESH,
                    scrape_reason=None,
                    metrics=NodeMetricSample(
                        active_sources=1,
                        occupied_streams=1,
                        received_bytes_total=1000,
                        sent_bytes_total=1000,
                    ),
                    metric_observed_at=now,
                    received_bitrate_bps=1000.0,
                    sent_bitrate_bps=1000.0,
                ),
            ),
        )
    )
    account = OperatorAccount(
        identity_source=OperatorIdentitySource.OIDC,
        id=ACCOUNT_ID,
        subject="browser-e2e-operator",
        display_name="Browser E2E operator",
        roles=frozenset({OperatorRole.ADMIN}),
        scopes=frozenset({"server:*"}),
        authz_version=1,
        enabled=True,
    )
    sessions = OperatorSessionControl(
        store=InMemoryOperatorSessionStore(accounts=(account,)),
        token_factory=lambda: secrets.token_urlsafe(32),
    )
    login = OidcLoginControl(
        provider=OidcProvider(
            issuer=f"{origin}/lab/idp",
            client_id="rtsp-proxy-browser-e2e",
            authorization_endpoint=f"{origin}/lab/idp/authorize",
            token_endpoint=f"{origin}/lab/idp/token",
            redirect_uri=f"{origin}/auth/oidc/callback",
        ),
        flows=InMemoryOidcFlowStore(),
        derivation_key=b"D" * 32,
        state_factory=lambda: secrets.token_urlsafe(32),
        token_endpoint=_LabTokenEndpoint(),
        claims_verifier=_LabClaimsVerifier(),
        account_resolver=lambda identity: (
            ACCOUNT_ID if identity.subject == account.subject else None
        ),
        sessions=sessions,
    )
    access_store = _LabAccessStore()
    app = create_app(
        Settings(role=RuntimeRole.WEB),
        camera_control=cameras,
        camera_mutation_control=mutations,
        fleet_snapshots=observations,
        fleet_snapshot_max_age_seconds=300,
        operator_sessions=sessions,
        operator_login=login,
        node_control=nodes,
        access_policy_control=AccessPolicyControl(store=access_store),
        access_grant_control=AccessGrantControl(
            store=access_store,  # type: ignore[arg-type]
            verifier=PepperVerifier(primary_key_id="lab", keys={"lab": b"L" * 32}),
            new_grant_id=uuid4,
            new_secret=lambda: DOWNSTREAM_SECRET_CANARY,
        ),
        access_secret_reveal_seconds=1,
    )

    @app.get("/lab/idp/authorize", include_in_schema=False)
    def lab_authorize(request: Request) -> HTMLResponse:
        state = request.query_params.get("state", "")
        redirect_uri = request.query_params.get("redirect_uri", "")
        callback = f"{redirect_uri}?{urlencode({'state': state, 'code': 'browser-e2e-code'})}"
        return HTMLResponse(
            "<!doctype html><html lang=\"ru\"><head><meta charset=\"utf-8\">"
            "<title>Browser E2E IdP</title></head><body><main><h1>Тестовый IdP</h1>"
            f"<a href=\"{html.escape(callback, quote=True)}\">Продолжить вход</a>"
            "</main></body></html>",
            headers={"Cache-Control": "no-store"},
        )

    @app.get("/lab/idp/token", include_in_schema=False)
    def lab_token() -> RedirectResponse:
        return RedirectResponse("/lab/idp/authorize", status_code=303)

    return app


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--certificate", required=True)
    parser.add_argument("--key", required=True)
    arguments = parser.parse_args()
    origin = f"https://{arguments.host}:{arguments.port}"
    uvicorn.run(
        build_lab_app(origin=origin),
        host=arguments.host,
        port=arguments.port,
        ssl_certfile=arguments.certificate,
        ssl_keyfile=arguments.key,
        access_log=False,
    )


if __name__ == "__main__":
    main()
