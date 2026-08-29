import argparse
import base64
import json
import logging
import os
import secrets
import threading
from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from datetime import timedelta
from pathlib import Path
from typing import Any, Protocol
from uuid import UUID, uuid4

import uvicorn
from fastapi import FastAPI

from rtsp_proxy.access import (
    AccessAttemptLimiter,
    AccessAuthorizer,
    AccessDecisionTelemetry,
    AccessGrantControl,
    AccessPepperFileError,
    AccessPolicyControl,
    PepperVerifier,
    load_pepper_verifier,
)
from rtsp_proxy.app import ManagementHstsBoundary, create_app, create_media_auth_app
from rtsp_proxy.config import RuntimeRole, Settings
from rtsp_proxy.database import PostgresNodeStore
from rtsp_proxy.health import RoleReadinessProvider
from rtsp_proxy.identifiers import generate_public_id
from rtsp_proxy.node_runtime import (
    UnixMediaNodeClientFactory,
    UnixNodeDisruptionObserver,
    UnixNodeMetricSource,
    UnixNodeRuntimeClient,
)
from rtsp_proxy.nodes import (
    CameraControl,
    NodeControl,
    NodeProvisioningPolicy,
    NodeRuntimeAction,
    tcp_port_is_bindable,
)
from rtsp_proxy.observability import (
    FleetCollector,
    IncidentControl,
    NotificationDispatcher,
    OperatorSecurityAlertDispatcher,
    PostgresObservabilityStore,
    SmtpNotificationTransport,
)
from rtsp_proxy.operator_access import (
    OperatorRole,
    OperatorSessionControl,
    PostgresOperatorSessionStore,
)
from rtsp_proxy.operator_identity import (
    BreakGlassControl,
    HttpsOidcDiscoveryEndpoint,
    HttpsOidcTokenEndpoint,
    OidcLoginControl,
    OidcProvider,
    PostgresBreakGlassStore,
    PostgresOidcAccountResolver,
    PostgresOidcFlowStore,
    Rs256OidcClaimsVerifier,
    read_operator_secret_file,
)
from rtsp_proxy.reconcile import (
    CameraMoveControl,
    CameraMoveReconciler,
    CameraMutationControl,
    CameraReconciler,
    CameraRuntimeObserver,
    ConfirmationTokenService,
    ReconcileCancelled,
    ReconcileCoordinator,
)

ENV_TO_FIELD = {
    "RTSP_PROXY_ROLE": "role",
    "RTSP_PROXY_HTTP_HOST": "http_host",
    "RTSP_PROXY_HTTP_PORT": "http_port",
    "RTSP_PROXY_MANAGEMENT_TLS_CERTIFICATE_FILE": "management_tls_certificate_file",
    "RTSP_PROXY_MANAGEMENT_TLS_PRIVATE_KEY_FILE": "management_tls_private_key_file",
    "RTSP_PROXY_AUTH_HOST": "auth_host",
    "RTSP_PROXY_AUTH_PORT": "auth_port",
    "RTSP_PROXY_AUTH_DATABASE_TIMEOUT_SECONDS": "auth_database_timeout_seconds",
    "RTSP_PROXY_ACCESS_PEPPER_FILE": "access_pepper_file",
    "RTSP_PROXY_SMTP_HOST": "smtp_host",
    "RTSP_PROXY_SMTP_PORT": "smtp_port",
    "RTSP_PROXY_SMTP_USERNAME": "smtp_username",
    "RTSP_PROXY_SMTP_PASSWORD_FILE": "smtp_password_file",
    "RTSP_PROXY_SMTP_CA_FILE": "smtp_ca_file",
    "RTSP_PROXY_SMTP_FROM_ADDRESS": "smtp_from_address",
    "RTSP_PROXY_SMTP_TO_ADDRESS": "smtp_to_address",
    "RTSP_PROXY_SMTP_STARTTLS": "smtp_starttls",
    "RTSP_PROXY_SMTP_TIMEOUT_SECONDS": "smtp_timeout_seconds",
    "RTSP_PROXY_NOTIFICATION_MAX_ATTEMPTS": "notification_max_attempts",
    "RTSP_PROXY_NOTIFICATION_RETRY_SECONDS": "notification_retry_seconds",
    "RTSP_PROXY_MAX_NODES": "max_nodes",
    "RTSP_PROXY_NODE_PORT_RANGE_START": "node_port_range_start",
    "RTSP_PROXY_NODE_PORT_RANGE_END": "node_port_range_end",
    "RTSP_PROXY_NODE_API_PORT_RANGE_START": "node_api_port_range_start",
    "RTSP_PROXY_NODE_API_PORT_RANGE_END": "node_api_port_range_end",
    "RTSP_PROXY_NODE_METRICS_PORT_RANGE_START": "node_metrics_port_range_start",
    "RTSP_PROXY_NODE_METRICS_PORT_RANGE_END": "node_metrics_port_range_end",
    "RTSP_PROXY_NODE_PORT_RESERVED": "node_port_reserved",
    "RTSP_PROXY_NODE_MANAGEMENT_FRESHNESS_SECONDS": ("node_management_freshness_seconds"),
    "RTSP_PROXY_NODE_LIFECYCLE_LOCK_POOL_SIZE": "node_lifecycle_lock_pool_size",
    "RTSP_PROXY_NODE_LIFECYCLE_LOCK_TIMEOUT_SECONDS": ("node_lifecycle_lock_timeout_seconds"),
    "RTSP_PROXY_NODE_RUNTIME_SOCKET": "node_runtime_socket",
    "RTSP_PROXY_NODE_RUNTIME_TIMEOUT_SECONDS": "node_runtime_timeout_seconds",
    "RTSP_PROXY_RECONCILE_INTERVAL_SECONDS": "reconcile_interval_seconds",
    "RTSP_PROXY_COLLECTOR_INTERVAL_SECONDS": "collector_interval_seconds",
    "RTSP_PROXY_DASHBOARD_POLL_INTERVAL_SECONDS": "dashboard_poll_interval_seconds",
    "RTSP_PROXY_CONFIRMATION_SECRET": "confirmation_secret",
    "RTSP_PROXY_OPERATOR_RECENT_MFA_SECONDS": "operator_recent_mfa_seconds",
    "RTSP_PROXY_NODE_RELEASE_ID": "node_release_id",
    "RTSP_PROXY_NODE_MEDIAMTX_BINARY_SHA256": "node_mediamtx_binary_sha256",
    "RTSP_PROXY_DATABASE_URL": "database_url",
    "RTSP_PROXY_OIDC_ISSUER": "oidc_issuer",
    "RTSP_PROXY_OIDC_CLIENT_ID": "oidc_client_id",
    "RTSP_PROXY_OIDC_AUTHORIZATION_ENDPOINT": "oidc_authorization_endpoint",
    "RTSP_PROXY_OIDC_TOKEN_ENDPOINT": "oidc_token_endpoint",
    "RTSP_PROXY_OIDC_JWKS_FILE": "oidc_jwks_file",
    "RTSP_PROXY_OIDC_REDIRECT_URI": "oidc_redirect_uri",
    "RTSP_PROXY_OIDC_CLIENT_SECRET_FILE": "oidc_client_secret_file",
    "RTSP_PROXY_OIDC_DERIVATION_KEY_FILE": "oidc_derivation_key_file",
    "RTSP_PROXY_OIDC_GROUP_ROLES_FILE": "oidc_group_roles_file",
    "RTSP_PROXY_OIDC_MFA_ACR": "oidc_mfa_acr",
    "RTSP_PROXY_OIDC_MFA_AMR": "oidc_mfa_amr",
    "RTSP_PROXY_BREAK_GLASS_ENCRYPTION_KEY_FILE": "break_glass_encryption_key_file",
}

LOGGER = logging.getLogger(__name__)

_BACKGROUND_DATABASE_TIMEOUT_MS = 2_000
_COLLECTOR_HELPER_TIMEOUT_SECONDS = 2.0
_COLLECTOR_CYCLE_TIMEOUT_SECONDS = 8.0
_COLLECTOR_JOIN_TIMEOUT_SECONDS = 20.0
_NOTIFIER_JOIN_GRACE_SECONDS = 8.0
_OPERATOR_HEALTH_JOIN_TIMEOUT_SECONDS = 20.0


class ConfigurationError(ValueError):
    """Runtime configuration cannot be loaded safely."""


@dataclass(frozen=True, slots=True)
class _OperatorSecurityRuntime:
    sessions: OperatorSessionControl
    login: OidcLoginControl
    break_glass: BreakGlassControl
    session_store: PostgresOperatorSessionStore
    flow_store: PostgresOidcFlowStore
    account_resolver: PostgresOidcAccountResolver
    break_glass_store: PostgresBreakGlassStore
    token_endpoint: HttpsOidcTokenEndpoint
    discovery_endpoint: HttpsOidcDiscoveryEndpoint
    claims_verifier: Rs256OidcClaimsVerifier

    def assert_ready(self) -> None:
        checks: tuple[tuple[str, Callable[[], None]], ...] = (
            ("session_store", self.session_store.assert_ready),
            ("flow_store", self.flow_store.assert_ready),
            ("break_glass_store", self.break_glass_store.assert_ready),
            ("claims_verifier", self.claims_verifier.assert_ready),
            ("discovery_endpoint", self.discovery_endpoint.assert_ready),
            ("token_endpoint", self.token_endpoint.assert_ready),
        )
        failures: dict[str, Exception] = {}
        with ThreadPoolExecutor(
            max_workers=len(checks),
            thread_name_prefix="rtsp-proxy-operator-probe",
        ) as executor:
            futures = {name: executor.submit(check) for name, check in checks}
            for name, _check in checks:
                try:
                    futures[name].result()
                except Exception as error:
                    failures[name] = error
        discovery_healthy = "discovery_endpoint" not in failures
        claim_health_error: Exception | None = None
        if "break_glass_store" not in failures:
            try:
                self.break_glass_store.record_claim_contract_health(healthy=discovery_healthy)
            except Exception as error:
                claim_health_error = error
        if failures:
            first_failed_name = next(name for name, _check in checks if name in failures)
            raise failures[first_failed_name]
        if claim_health_error is not None:
            raise claim_health_error

    def close(self) -> None:
        self.break_glass_store.close()
        self.account_resolver.close()
        self.flow_store.close()
        self.session_store.close()


class _OperatorHealthState:
    """Single-writer health cache; HTTP readiness never starts provider probes."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._ready = False

    def probe(self, runtime: _OperatorSecurityRuntime) -> None:
        try:
            runtime.assert_ready()
        except Exception:
            with self._lock:
                self._ready = False
            raise
        with self._lock:
            self._ready = True

    def assert_ready(self) -> None:
        with self._lock:
            ready = self._ready
        if not ready:
            raise RuntimeError("operator_identity_unavailable")


def load_settings(environ: Mapping[str, str] | None = None) -> Settings:
    values = os.environ if environ is None else environ
    config: dict[str, Any] = {}

    config_file = values.get("RTSP_PROXY_CONFIG_FILE")
    if config_file:
        config.update(_read_config_file(Path(config_file)))

    for environment_name, field_name in ENV_TO_FIELD.items():
        if environment_name in values:
            raw_value: Any = values[environment_name]
            if field_name in {"oidc_mfa_acr", "oidc_mfa_amr"}:
                raw_value = tuple(item.strip() for item in raw_value.split(",") if item.strip())
            config[field_name] = raw_value

    return Settings.model_validate(config)


def create_app_from_environment() -> FastAPI:
    return _create_runtime_app(load_settings())


def _create_runtime_app(settings: Settings) -> FastAPI:
    if settings.role is RuntimeRole.AUTH:
        raise ConfigurationError("web_role_required")
    store = _open_verified_store(settings)
    if store is None:
        return create_app(settings)
    node_runtime = (
        None
        if settings.node_runtime_socket is None
        else UnixNodeRuntimeClient(
            socket_path=settings.node_runtime_socket,
            timeout_seconds=settings.node_runtime_timeout_seconds,
        )
    )
    media_factory = (
        None
        if settings.node_runtime_socket is None
        else UnixMediaNodeClientFactory(
            socket_path=settings.node_runtime_socket,
            timeout_seconds=min(10, settings.node_runtime_timeout_seconds),
        )
    )
    node_control = NodeControl(
        store=store,
        choose_port=secrets.choice,
        new_node_id=uuid4,
        is_port_bindable=tcp_port_is_bindable,
        node_runtime=node_runtime,
        disruption_observer=(
            None if media_factory is None else UnixNodeDisruptionObserver(media_nodes=media_factory)
        ),
        provision_on_create=node_runtime is not None,
        recovery_workers=settings.node_lifecycle_lock_pool_size,
        confirmations=(
            None
            if settings.confirmation_secret is None
            else ConfirmationTokenService(
                secret=settings.confirmation_secret.encode("utf-8"),
                lifetime_seconds=30,
            )
        ),
        reconfigure_release_id=settings.node_release_id,
        reconfigure_mediamtx_binary_sha256=settings.node_mediamtx_binary_sha256,
    )
    provisioning_policy = NodeProvisioningPolicy(
        port_range_start=settings.node_port_range_start,
        port_range_end=settings.node_port_range_end,
        max_nodes=settings.max_nodes,
        reserved_ports=settings.node_port_reserved,
        api_ports=tuple(
            range(
                settings.node_api_port_range_start,
                settings.node_api_port_range_end + 1,
            )
        ),
        metrics_ports=tuple(
            range(
                settings.node_metrics_port_range_start,
                settings.node_metrics_port_range_end + 1,
            )
        ),
        release_id=settings.node_release_id,
        mediamtx_binary_sha256=settings.node_mediamtx_binary_sha256,
        management_freshness_seconds=settings.node_management_freshness_seconds,
    )

    def recover_runtime_state() -> None:
        node_control.recover_runtime_state()

    camera_runtime = (
        None
        if media_factory is None
        else CameraRuntimeObserver(store=store, media_nodes=media_factory)
    )
    move_control = (
        None
        if camera_runtime is None or settings.confirmation_secret is None
        else CameraMoveControl(
            store=store,
            runtime=camera_runtime,
            confirmations=ConfirmationTokenService(
                secret=settings.confirmation_secret.encode("utf-8"),
                lifetime_seconds=30,
            ),
            new_move_id=uuid4,
            management_freshness_seconds=settings.node_management_freshness_seconds,
        )
    )
    mutation_control = (
        None
        if media_factory is None or settings.confirmation_secret is None
        else CameraMutationControl(
            store=store,
            media_nodes=media_factory,
            confirmations=ConfirmationTokenService(
                secret=settings.confirmation_secret.encode("utf-8"),
                lifetime_seconds=30,
            ),
        )
    )
    assert settings.database_url is not None
    observability = (
        PostgresObservabilityStore(
            settings.database_url,
            statement_timeout_ms=_BACKGROUND_DATABASE_TIMEOUT_MS,
        )
        if store.schema_supports_operator_login()
        else None
    )
    try:
        operator_security = (
            _open_operator_security(settings) if settings.operator_auth_enabled else None
        )
    except Exception:
        if observability is not None:
            observability.close()
        store.close()
        raise

    operator_health_stop = threading.Event()
    operator_health_thread: threading.Thread | None = None
    operator_health_state = _OperatorHealthState()

    def monitor_operator_health() -> None:
        while not operator_health_stop.wait(30):
            assert operator_security is not None
            try:
                operator_health_state.probe(operator_security)
            except Exception:
                LOGGER.exception("operator identity health check failed")

    def start_runtime() -> None:
        nonlocal operator_health_thread
        if node_runtime is not None:
            recover_runtime_state()
        if operator_security is not None:
            operator_health_state.probe(operator_security)
            operator_health_thread = threading.Thread(
                target=monitor_operator_health,
                name="rtsp-proxy-operator-health",
                daemon=False,
            )
            operator_health_thread.start()

    def close_runtime_stores() -> None:
        operator_health_stop.set()
        try:
            if operator_health_thread is not None:
                operator_health_thread.join(timeout=_OPERATOR_HEALTH_JOIN_TIMEOUT_SECONDS)
                if operator_health_thread.is_alive():
                    raise RuntimeError("operator_health_shutdown_timeout")
            if operator_security is not None:
                operator_security.close()
        finally:
            try:
                if observability is not None:
                    observability.close()
            finally:
                store.close()

    readiness_checks: dict[str, Callable[[], None]] = {
        "database": store.assert_schema_compatible,
        "schema": store.assert_schema_compatible,
    }
    readiness_checks["session_store"] = (
        store.assert_schema_compatible
        if operator_security is None
        else operator_health_state.assert_ready
    )

    return create_app(
        settings,
        readiness=RoleReadinessProvider(readiness_checks),
        node_control=node_control,
        camera_control=CameraControl(
            store=store,
            new_camera_id=uuid4,
            new_public_id=generate_public_id,
            management_freshness_seconds=settings.node_management_freshness_seconds,
            ensure_automatic_capacity=(
                None
                if node_runtime is None
                else lambda context: node_control.ensure_automatic_capacity(
                    provisioning_policy,
                    mutation_context=context,
                )
            ),
        ),
        camera_move_control=move_control,
        camera_mutation_control=mutation_control,
        camera_runtime_observer=camera_runtime,
        access_policy_control=AccessPolicyControl(store=store),
        access_grant_control=(
            None
            if settings.access_pepper_file is None
            else AccessGrantControl(
                store=store,
                verifier=_load_access_verifier(settings),
                new_grant_id=uuid4,
            )
        ),
        fleet_snapshots=observability,
        fleet_snapshot_max_age_seconds=settings.collector_interval_seconds * 3,
        operator_sessions=(None if operator_security is None else operator_security.sessions),
        operator_login=None if operator_security is None else operator_security.login,
        break_glass=(None if operator_security is None else operator_security.break_glass),
        startup=start_runtime,
        shutdown=close_runtime_stores,
    )


def _open_operator_security(
    settings: Settings,
    *,
    trusted_owner_uid: int | None = None,
) -> _OperatorSecurityRuntime:
    if not settings.operator_auth_enabled or settings.database_url is None:
        raise ConfigurationError("operator_auth_configuration_incomplete")
    assert settings.oidc_issuer is not None
    assert settings.oidc_client_id is not None
    assert settings.oidc_authorization_endpoint is not None
    assert settings.oidc_token_endpoint is not None
    assert settings.oidc_jwks_file is not None
    assert settings.oidc_redirect_uri is not None
    assert settings.oidc_client_secret_file is not None
    assert settings.oidc_derivation_key_file is not None
    assert settings.oidc_group_roles_file is not None
    assert settings.break_glass_encryption_key_file is not None
    credential_owner_uid = os.geteuid() if trusted_owner_uid is None else trusted_owner_uid
    try:
        client_secret = _decode_single_line(
            read_operator_secret_file(
                settings.oidc_client_secret_file,
                trusted_owner_uid=credential_owner_uid,
                maximum_bytes=4096,
            )
        )
        derivation_key = _decode_operator_key(
            read_operator_secret_file(
                settings.oidc_derivation_key_file,
                trusted_owner_uid=credential_owner_uid,
                maximum_bytes=256,
            )
        )
        encryption_key = _decode_operator_key(
            read_operator_secret_file(
                settings.break_glass_encryption_key_file,
                trusted_owner_uid=credential_owner_uid,
                maximum_bytes=256,
            )
        )
        jwks = _decode_json_object(
            read_operator_secret_file(
                settings.oidc_jwks_file,
                trusted_owner_uid=credential_owner_uid,
            )
        )
        group_roles = _decode_group_roles(
            read_operator_secret_file(
                settings.oidc_group_roles_file,
                trusted_owner_uid=credential_owner_uid,
            )
        )
    except (UnicodeError, ValueError, json.JSONDecodeError):
        raise ConfigurationError("operator_auth_file_invalid") from None

    timeout_ms = round(settings.auth_database_timeout_seconds * 1000)
    session_store = PostgresOperatorSessionStore(
        settings.database_url,
        statement_timeout_ms=timeout_ms,
    )
    flow_store: PostgresOidcFlowStore | None = None
    account_resolver: PostgresOidcAccountResolver | None = None
    break_glass_store: PostgresBreakGlassStore | None = None
    try:
        flow_store = PostgresOidcFlowStore(
            settings.database_url,
            statement_timeout_ms=timeout_ms,
        )
        account_resolver = PostgresOidcAccountResolver(
            settings.database_url,
            issuer=settings.oidc_issuer,
            statement_timeout_ms=timeout_ms,
        )
        break_glass_store = PostgresBreakGlassStore(
            settings.database_url,
            encryption_key=encryption_key,
            statement_timeout_ms=timeout_ms,
        )
        sessions = OperatorSessionControl(
            store=session_store,
            token_factory=lambda: secrets.token_urlsafe(32),
        )
        provider = OidcProvider(
            issuer=settings.oidc_issuer,
            client_id=settings.oidc_client_id,
            authorization_endpoint=settings.oidc_authorization_endpoint,
            token_endpoint=settings.oidc_token_endpoint,
            redirect_uri=settings.oidc_redirect_uri,
        )
        token_endpoint = HttpsOidcTokenEndpoint(
            token_endpoint=settings.oidc_token_endpoint,
            client_id=settings.oidc_client_id,
            client_secret=client_secret,
            redirect_uri=settings.oidc_redirect_uri,
        )
        discovery_endpoint = HttpsOidcDiscoveryEndpoint(
            issuer=settings.oidc_issuer,
            authorization_endpoint=settings.oidc_authorization_endpoint,
            token_endpoint=settings.oidc_token_endpoint,
        )
        claims_verifier = Rs256OidcClaimsVerifier(
            issuer=settings.oidc_issuer,
            client_id=settings.oidc_client_id,
            jwks=jwks,
            group_roles=group_roles,
            accepted_mfa_acr=frozenset(settings.oidc_mfa_acr),
            required_mfa_amr=frozenset(settings.oidc_mfa_amr),
        )
        login = OidcLoginControl(
            provider=provider,
            flows=flow_store,
            derivation_key=derivation_key,
            state_factory=lambda: secrets.token_urlsafe(32),
            token_endpoint=token_endpoint,
            claims_verifier=claims_verifier,
            account_resolver=account_resolver.resolve,
            sessions=sessions,
        )
        return _OperatorSecurityRuntime(
            sessions=sessions,
            login=login,
            break_glass=BreakGlassControl(store=break_glass_store, sessions=sessions),
            session_store=session_store,
            flow_store=flow_store,
            account_resolver=account_resolver,
            break_glass_store=break_glass_store,
            token_endpoint=token_endpoint,
            discovery_endpoint=discovery_endpoint,
            claims_verifier=claims_verifier,
        )
    except Exception:
        if break_glass_store is not None:
            break_glass_store.close()
        if account_resolver is not None:
            account_resolver.close()
        if flow_store is not None:
            flow_store.close()
        session_store.close()
        raise


def _decode_single_line(payload: bytes) -> str:
    value = payload.decode("utf-8").rstrip("\n")
    if not value or "\n" in value or len(value) > 4096:
        raise ValueError("operator_secret_invalid")
    return value


def _decode_operator_key(payload: bytes) -> bytes:
    encoded = payload.rstrip(b"\n")
    if b"\n" in encoded or len(encoded) != 43:
        raise ValueError("operator_key_invalid")
    try:
        value = base64.urlsafe_b64decode(encoded + b"=")
    except (ValueError, TypeError):
        raise ValueError("operator_key_invalid") from None
    if len(value) != 32 or base64.urlsafe_b64encode(value).rstrip(b"=") != encoded:
        raise ValueError("operator_key_invalid")
    return value


def _decode_json_object(payload: bytes) -> dict[str, object]:
    value = json.loads(payload)
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ValueError("operator_json_invalid")
    return value


def _decode_group_roles(payload: bytes) -> dict[str, frozenset[OperatorRole]]:
    value = _decode_json_object(payload)
    result: dict[str, frozenset[OperatorRole]] = {}
    for group, raw_roles in value.items():
        if (
            not 1 <= len(group) <= 256
            or not isinstance(raw_roles, list)
            or not raw_roles
            or not all(isinstance(role, str) for role in raw_roles)
            or len(raw_roles) != len(set(raw_roles))
        ):
            raise ValueError("operator_group_roles_invalid")
        roles = frozenset(OperatorRole(role) for role in raw_roles)
        if OperatorRole.BREAK_GLASS in roles:
            raise ValueError("operator_group_roles_invalid")
        result[group] = roles
    if not result:
        raise ValueError("operator_group_roles_invalid")
    return result


def create_background_app(
    settings: Settings,
    *,
    expected_role: RuntimeRole,
) -> FastAPI:
    if expected_role in {RuntimeRole.WEB, RuntimeRole.AUTH} or settings.role in {
        RuntimeRole.WEB,
        RuntimeRole.AUTH,
    }:
        raise ConfigurationError("background_role_required")
    if settings.role is not expected_role:
        raise ConfigurationError("background_role_mismatch")
    if expected_role is RuntimeRole.PROBE:
        raise ConfigurationError("probe_role_not_implemented")
    store = _open_verified_store(settings)
    startup: Callable[[], None] | None = None
    shutdown: Callable[[], None] | None = None if store is None else store.close
    worker_security_alerts_enabled: bool | None = None
    if (
        store is not None
        and expected_role is RuntimeRole.RECONCILER
        and settings.node_runtime_socket is not None
    ):
        media = UnixMediaNodeClientFactory(
            socket_path=settings.node_runtime_socket,
            timeout_seconds=min(10, settings.node_runtime_timeout_seconds),
        )
        coordinator = ReconcileCoordinator(
            store=store,
            cameras=CameraReconciler(store=store, media_nodes=media),
            moves=CameraMoveReconciler(store=store, media_nodes=media),
        )
        stop = threading.Event()
        thread: threading.Thread | None = None

        def reconcile_loop() -> None:
            while not stop.is_set():
                try:
                    coordinator.run_once(cancelled=stop.is_set)
                except ReconcileCancelled:
                    break
                except Exception:
                    LOGGER.exception("camera reconcile cycle failed")
                stop.wait(settings.reconcile_interval_seconds)

        def start_reconciler() -> None:
            nonlocal thread
            thread = threading.Thread(
                target=reconcile_loop,
                name="rtsp-proxy-reconciler",
                daemon=False,
            )
            thread.start()

        def stop_reconciler() -> None:
            stop.set()
            try:
                if thread is not None:
                    thread.join(
                        timeout=max(
                            settings.reconcile_interval_seconds,
                            min(10, settings.node_runtime_timeout_seconds),
                        )
                        + 2
                    )
                    if thread.is_alive():
                        raise RuntimeError("reconciler_shutdown_timeout")
            finally:
                if thread is None or not thread.is_alive():
                    store.close()

        startup = start_reconciler
        shutdown = stop_reconciler
    if (
        store is not None
        and expected_role is RuntimeRole.COLLECTOR
        and settings.node_runtime_socket is not None
    ):
        collector_store = store
        collector_database_timeout_ms = _BACKGROUND_DATABASE_TIMEOUT_MS
        observability = PostgresObservabilityStore(
            settings.database_url or "",
            statement_timeout_ms=collector_database_timeout_ms,
        )
        node_runtime = UnixNodeRuntimeClient(
            socket_path=settings.node_runtime_socket,
            timeout_seconds=min(
                _COLLECTOR_HELPER_TIMEOUT_SECONDS,
                settings.node_runtime_timeout_seconds,
            ),
        )

        class ReadOnlyRuntimeObserver:
            def observe_node(self, node_id: UUID) -> Any:
                node = collector_store.get_node(node_id)
                if node is None:
                    raise RuntimeError("node_not_found")
                observation = node_runtime.execute(NodeRuntimeAction.OBSERVE, node)
                return replace(
                    node,
                    runtime_state=observation.state,
                    health=observation.health,
                    applied_revision=observation.applied_revision,
                    config_compatible=observation.config_compatible,
                    management_fresh=observation.management_fresh,
                    process_id=observation.process_id,
                    process_start_ticks=observation.process_start_ticks,
                    process_boot_id=observation.process_boot_id,
                    observed_config_sha256=observation.config_sha256,
                    observed_release_id=observation.release_id,
                )

        metrics = UnixNodeMetricSource(
            media_nodes=UnixMediaNodeClientFactory(
                socket_path=settings.node_runtime_socket,
                timeout_seconds=min(
                    _COLLECTOR_HELPER_TIMEOUT_SECONDS,
                    settings.node_runtime_timeout_seconds,
                ),
            )
        )
        stop = threading.Event()
        collector = FleetCollector(
            nodes=store,
            runtime=ReadOnlyRuntimeObserver(),
            metrics=metrics,
            observations=observability,
            incidents=IncidentControl(store=observability),
            max_nodes=settings.max_nodes,
            external_port_capacity=len(
                set(
                    range(
                        settings.node_port_range_start,
                        settings.node_port_range_end + 1,
                    )
                ).difference(settings.node_port_reserved)
            ),
            cancelled=stop.is_set,
            collection_interval_seconds=settings.collector_interval_seconds,
            cycle_timeout_seconds=min(
                settings.collector_interval_seconds,
                _COLLECTOR_CYCLE_TIMEOUT_SECONDS,
            ),
        )
        collector_thread: threading.Thread | None = None

        def collector_loop() -> None:
            while not stop.is_set():
                try:
                    collector.run_once()
                except Exception:
                    LOGGER.exception("fleet collector cycle failed")
                stop.wait(settings.collector_interval_seconds)

        def start_collector() -> None:
            nonlocal collector_thread
            collector_thread = threading.Thread(
                target=collector_loop,
                name="rtsp-proxy-collector",
                daemon=False,
            )
            collector_thread.start()

        def stop_collector() -> None:
            stop.set()
            try:
                if collector_thread is not None:
                    collector_thread.join(timeout=_COLLECTOR_JOIN_TIMEOUT_SECONDS)
                    if collector_thread.is_alive():
                        raise RuntimeError("collector_shutdown_timeout")
            finally:
                if collector_thread is None or not collector_thread.is_alive():
                    try:
                        collector.close()
                    finally:
                        try:
                            observability.close()
                        finally:
                            store.close()

        startup = start_collector
        shutdown = stop_collector
    if store is not None and expected_role is RuntimeRole.WORKER and settings.smtp_host is not None:
        assert settings.database_url is not None
        assert settings.smtp_username is not None
        assert settings.smtp_password_file is not None
        assert settings.smtp_from_address is not None
        assert settings.smtp_to_address is not None
        observability = PostgresObservabilityStore(
            settings.database_url,
            statement_timeout_ms=_BACKGROUND_DATABASE_TIMEOUT_MS,
        )
        transport = SmtpNotificationTransport(
            host=settings.smtp_host,
            port=settings.smtp_port,
            username=settings.smtp_username,
            password_file=settings.smtp_password_file,
            ca_file=settings.smtp_ca_file,
            from_address=settings.smtp_from_address,
            to_address=settings.smtp_to_address,
            starttls=settings.smtp_starttls,
            timeout_seconds=settings.smtp_timeout_seconds,
            trusted_password_owner_uid=os.geteuid(),
        )
        dispatcher = NotificationDispatcher(
            store=observability,
            transport=transport,
            max_attempts=settings.notification_max_attempts,
            retry_delay=timedelta(seconds=settings.notification_retry_seconds),
        )
        worker_security_alerts_enabled = store.schema_supports_operator_login()
        security_dispatcher = (
            OperatorSecurityAlertDispatcher(
                store=observability,
                transport=transport,
                max_attempts=settings.notification_max_attempts,
                retry_delay=timedelta(seconds=settings.notification_retry_seconds),
            )
            if worker_security_alerts_enabled
            else None
        )
        stop = threading.Event()
        notification_thread: threading.Thread | None = None

        def notification_loop() -> None:
            prefer_security = True
            while not stop.is_set():
                try:
                    delivered: object | None
                    if security_dispatcher is None:
                        delivered = dispatcher.run_once()
                    else:
                        delivered, prefer_security = _dispatch_notification_fairly(
                            security_dispatcher=security_dispatcher,
                            incident_dispatcher=dispatcher,
                            prefer_security=prefer_security,
                        )
                except Exception:
                    LOGGER.exception("notification delivery cycle failed")
                    delivered = None
                    prefer_security = not prefer_security
                if delivered is None:
                    stop.wait(1)

        def start_notifications() -> None:
            nonlocal notification_thread
            notification_thread = threading.Thread(
                target=notification_loop,
                name="rtsp-proxy-notifications",
                daemon=False,
            )
            notification_thread.start()

        def stop_notifications() -> None:
            stop.set()
            try:
                if notification_thread is not None:
                    notification_thread.join(
                        timeout=(settings.smtp_timeout_seconds + _NOTIFIER_JOIN_GRACE_SECONDS)
                    )
                    if notification_thread.is_alive():
                        raise RuntimeError("notification_worker_shutdown_timeout")
            finally:
                if notification_thread is None or not notification_thread.is_alive():
                    try:
                        observability.close()
                    finally:
                        store.close()

        startup = start_notifications
        shutdown = stop_notifications
    return create_app(
        settings,
        readiness=_background_readiness(
            settings,
            expected_role=expected_role,
            store=store,
            worker_security_alerts_enabled=worker_security_alerts_enabled,
        ),
        startup=startup,
        shutdown=shutdown,
    )


class _NotificationCycleDispatcher(Protocol):
    def run_once(self) -> object | None: ...


def _dispatch_notification_fairly(
    *,
    security_dispatcher: _NotificationCycleDispatcher,
    incident_dispatcher: _NotificationCycleDispatcher,
    prefer_security: bool,
) -> tuple[object | None, bool]:
    if prefer_security:
        delivered = security_dispatcher.run_once()
        if delivered is None:
            delivered = incident_dispatcher.run_once()
    else:
        delivered = incident_dispatcher.run_once()
        if delivered is None:
            delivered = security_dispatcher.run_once()
    return delivered, not prefer_security


def _background_readiness(
    settings: Settings,
    *,
    expected_role: RuntimeRole,
    store: PostgresNodeStore | None,
    worker_security_alerts_enabled: bool | None = None,
) -> RoleReadinessProvider:
    if store is None:
        return RoleReadinessProvider({})

    def database_ready() -> None:
        store.assert_schema_compatible()

    def media_helper_ready() -> None:
        path = settings.node_runtime_socket
        if path is None:
            raise RuntimeError("node_runtime_socket_required")
        UnixNodeRuntimeClient(
            socket_path=path,
            timeout_seconds=min(1, settings.node_runtime_timeout_seconds),
        ).health()

    checks: dict[str, Callable[[], None]] = {
        "database": database_ready,
        "schema": store.assert_schema_compatible,
    }
    if expected_role is RuntimeRole.WORKER:
        assert settings.database_url is not None

        def outbox_ready() -> None:
            require_security_alerts = store.schema_supports_operator_login()
            if require_security_alerts and worker_security_alerts_enabled is not True:
                raise RuntimeError("security_dispatcher_restart_required")
            observability = PostgresObservabilityStore(
                settings.database_url or "",
                statement_timeout_ms=_BACKGROUND_DATABASE_TIMEOUT_MS,
            )
            try:
                observability.assert_notification_ready(
                    require_security_alerts=require_security_alerts,
                )
            finally:
                observability.close()

        checks["outbox"] = outbox_ready
    elif expected_role is RuntimeRole.RECONCILER:
        checks["media_adapter"] = media_helper_ready
    elif expected_role is RuntimeRole.COLLECTOR:
        checks["media_metrics"] = media_helper_ready
        assert settings.database_url is not None

        def collector_store_ready() -> None:
            observability = PostgresObservabilityStore(
                settings.database_url or "",
                statement_timeout_ms=_BACKGROUND_DATABASE_TIMEOUT_MS,
            )
            try:
                observability.assert_collector_ready()
            finally:
                observability.close()

        checks["collector_store"] = collector_store_ready
    return RoleReadinessProvider(checks)


def _open_verified_store(settings: Settings) -> PostgresNodeStore | None:
    if settings.database_url is None:
        return None
    store = PostgresNodeStore(
        settings.database_url,
        lifecycle_lock_pool_size=settings.node_lifecycle_lock_pool_size,
        lifecycle_lock_timeout_seconds=settings.node_lifecycle_lock_timeout_seconds,
        statement_timeout_ms=(
            round(settings.auth_database_timeout_seconds * 1000)
            if settings.role is RuntimeRole.AUTH
            else (
                _BACKGROUND_DATABASE_TIMEOUT_MS
                if settings.role in {RuntimeRole.WEB, RuntimeRole.COLLECTOR, RuntimeRole.WORKER}
                else None
            )
        ),
    )
    try:
        store.assert_schema_compatible()
    except Exception:
        store.close()
        raise
    return store


def run_web(
    *,
    management_tls_certificate_file: Path | None = None,
    management_tls_private_key_file: Path | None = None,
) -> None:
    if (management_tls_certificate_file is None) != (management_tls_private_key_file is None):
        raise ConfigurationError("management_tls_configuration_incomplete")
    environment = dict(os.environ)
    if management_tls_certificate_file is not None:
        assert management_tls_private_key_file is not None
        environment["RTSP_PROXY_MANAGEMENT_TLS_CERTIFICATE_FILE"] = str(
            management_tls_certificate_file
        )
        environment["RTSP_PROXY_MANAGEMENT_TLS_PRIVATE_KEY_FILE"] = str(
            management_tls_private_key_file
        )
    settings = load_settings(environment)
    if settings.role is not RuntimeRole.WEB:
        raise ConfigurationError("web_role_required")
    application: Any = _create_runtime_app(settings)
    if settings.management_tls_certificate_file is not None:
        application = ManagementHstsBoundary(application)
    uvicorn.run(
        application,
        host=str(settings.http_host),
        port=settings.http_port,
        access_log=False,
        ssl_certfile=(
            None
            if settings.management_tls_certificate_file is None
            else str(settings.management_tls_certificate_file)
        ),
        ssl_keyfile=(
            None
            if settings.management_tls_private_key_file is None
            else str(settings.management_tls_private_key_file)
        ),
    )


def run_web_cli(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Run the RTSP Proxy management HTTPS server")
    parser.add_argument("--management-tls-certificate-file", type=Path)
    parser.add_argument("--management-tls-private-key-file", type=Path)
    arguments = parser.parse_args(argv)
    run_web(
        management_tls_certificate_file=arguments.management_tls_certificate_file,
        management_tls_private_key_file=arguments.management_tls_private_key_file,
    )


def run_auth() -> None:
    settings = load_settings()
    if settings.role is not RuntimeRole.AUTH:
        raise ConfigurationError("auth_role_required")
    store = _open_verified_store(settings)
    if store is None:
        raise ConfigurationError("database_url_required")
    verifier = _load_access_verifier(settings)
    telemetry = AccessDecisionTelemetry()
    uvicorn.run(
        create_media_auth_app(
            authorizer=AccessAuthorizer(
                store=store,
                verifier=verifier,
                attempts=AccessAttemptLimiter(),
                decision_sink=telemetry,
            ),
            callback_verifier=verifier,
            telemetry=telemetry,
            readiness=store.assert_schema_compatible,
            shutdown=store.close,
        ),
        host=str(settings.auth_host),
        port=settings.auth_port,
    )


def run_background(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="rtsp-proxy-role",
        description="Run one validated RTSP Proxy background role.",
    )
    parser.add_argument(
        "--expected-role",
        choices=[
            role.value for role in RuntimeRole if role not in {RuntimeRole.WEB, RuntimeRole.AUTH}
        ],
        required=True,
    )
    arguments = parser.parse_args(argv)
    settings = load_settings()
    uvicorn.run(
        create_background_app(
            settings,
            expected_role=RuntimeRole(arguments.expected_role),
        ),
        host=str(settings.http_host),
        port=settings.http_port,
    )


def _read_config_file(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ConfigurationError("invalid_config_file") from error
    if not isinstance(value, dict):
        raise ConfigurationError("invalid_config_file")
    return value


def _load_access_verifier(settings: Settings) -> PepperVerifier:
    path = settings.access_pepper_file
    if path is None:
        raise ConfigurationError("access_pepper_file_required")
    try:
        return load_pepper_verifier(path)
    except AccessPepperFileError as error:
        raise ConfigurationError("access_pepper_file_unsafe") from error
