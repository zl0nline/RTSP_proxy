import argparse
import json
import logging
import os
import secrets
import threading
from collections.abc import Callable, Mapping, Sequence
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from typing import Any
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
from rtsp_proxy.app import create_app, create_media_auth_app
from rtsp_proxy.config import RuntimeRole, Settings
from rtsp_proxy.database import PostgresNodeStore
from rtsp_proxy.health import RoleReadinessProvider
from rtsp_proxy.identifiers import generate_public_id
from rtsp_proxy.node_runtime import (
    UnixMediaNodeClientFactory,
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
    PostgresObservabilityStore,
    SmtpNotificationTransport,
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
    "RTSP_PROXY_CONFIRMATION_SECRET": "confirmation_secret",
    "RTSP_PROXY_NODE_RELEASE_ID": "node_release_id",
    "RTSP_PROXY_NODE_MEDIAMTX_BINARY_SHA256": "node_mediamtx_binary_sha256",
    "RTSP_PROXY_DATABASE_URL": "database_url",
}

LOGGER = logging.getLogger(__name__)

_BACKGROUND_DATABASE_TIMEOUT_MS = 2_000
_COLLECTOR_HELPER_TIMEOUT_SECONDS = 2.0
_COLLECTOR_CYCLE_TIMEOUT_SECONDS = 8.0
_COLLECTOR_JOIN_TIMEOUT_SECONDS = 20.0
_NOTIFIER_JOIN_GRACE_SECONDS = 8.0


class ConfigurationError(ValueError):
    """Runtime configuration cannot be loaded safely."""


def load_settings(environ: Mapping[str, str] | None = None) -> Settings:
    values = os.environ if environ is None else environ
    config: dict[str, Any] = {}

    config_file = values.get("RTSP_PROXY_CONFIG_FILE")
    if config_file:
        config.update(_read_config_file(Path(config_file)))

    for environment_name, field_name in ENV_TO_FIELD.items():
        if environment_name in values:
            config[field_name] = values[environment_name]

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
    node_control = NodeControl(
        store=store,
        choose_port=secrets.choice,
        new_node_id=uuid4,
        is_port_bindable=tcp_port_is_bindable,
        node_runtime=node_runtime,
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

    media_factory = (
        None
        if settings.node_runtime_socket is None
        else UnixMediaNodeClientFactory(
            socket_path=settings.node_runtime_socket,
            timeout_seconds=min(10, settings.node_runtime_timeout_seconds),
        )
    )
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
        if store.schema_is_current()
        else None
    )

    def close_runtime_stores() -> None:
        if observability is not None:
            observability.close()
        store.close()

    return create_app(
        settings,
        node_control=node_control,
        camera_control=CameraControl(
            store=store,
            new_camera_id=uuid4,
            new_public_id=generate_public_id,
            management_freshness_seconds=settings.node_management_freshness_seconds,
            ensure_automatic_capacity=(
                None
                if node_runtime is None
                else lambda: node_control.ensure_automatic_capacity(provisioning_policy)
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
        startup=(None if node_runtime is None else recover_runtime_state),
        shutdown=close_runtime_stores,
    )


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
    if store is not None and expected_role in {
        RuntimeRole.COLLECTOR,
        RuntimeRole.WORKER,
    }:
        store.assert_schema_current()
    startup: Callable[[], None] | None = None
    shutdown: Callable[[], None] | None = None if store is None else store.close
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
    if (
        store is not None
        and expected_role is RuntimeRole.WORKER
        and settings.smtp_host is not None
    ):
        assert settings.database_url is not None
        assert settings.smtp_username is not None
        assert settings.smtp_password_file is not None
        assert settings.smtp_from_address is not None
        assert settings.smtp_to_address is not None
        observability = PostgresObservabilityStore(
            settings.database_url,
            statement_timeout_ms=_BACKGROUND_DATABASE_TIMEOUT_MS,
        )
        dispatcher = NotificationDispatcher(
            store=observability,
            transport=SmtpNotificationTransport(
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
            ),
            max_attempts=settings.notification_max_attempts,
            retry_delay=timedelta(seconds=settings.notification_retry_seconds),
        )
        stop = threading.Event()
        notification_thread: threading.Thread | None = None

        def notification_loop() -> None:
            while not stop.is_set():
                try:
                    delivered = dispatcher.run_once()
                except Exception:
                    LOGGER.exception("notification delivery cycle failed")
                    delivered = None
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
                        timeout=(
                            settings.smtp_timeout_seconds
                            + _NOTIFIER_JOIN_GRACE_SECONDS
                        )
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
        ),
        startup=startup,
        shutdown=shutdown,
    )


def _background_readiness(
    settings: Settings,
    *,
    expected_role: RuntimeRole,
    store: PostgresNodeStore | None,
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
            observability = PostgresObservabilityStore(
                settings.database_url or "",
                statement_timeout_ms=_BACKGROUND_DATABASE_TIMEOUT_MS,
            )
            try:
                observability.assert_notification_ready()
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
                if settings.role in {RuntimeRole.COLLECTOR, RuntimeRole.WORKER}
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


def run_web() -> None:
    settings = load_settings()
    if settings.role is not RuntimeRole.WEB:
        raise ConfigurationError("web_role_required")
    uvicorn.run(
        _create_runtime_app(settings),
        host=str(settings.http_host),
        port=settings.http_port,
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
            role.value
            for role in RuntimeRole
            if role not in {RuntimeRole.WEB, RuntimeRole.AUTH}
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
