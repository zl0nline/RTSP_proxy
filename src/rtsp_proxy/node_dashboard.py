from __future__ import annotations

from collections.abc import Callable
from uuid import UUID, uuid4

from fastapi import APIRouter, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse

from rtsp_proxy.config import Settings
from rtsp_proxy.dashboard import (
    DASHBOARD_CSP,
    DashboardUnavailable,
    render_node_create,
    render_node_registration,
    render_unavailable,
)
from rtsp_proxy.dashboard_forms import DashboardForm, DashboardFormInvalid
from rtsp_proxy.node_operator import node_mutation_context, operator_node_command
from rtsp_proxy.nodes import (
    MaximumNodesReached,
    MediaNode,
    NodeCommandFence,
    NodeControl,
    NodeLifecycleBusy,
    NodeLifecycleConflict,
    NodeManagementPortRangeExhausted,
    NodeMutationContext,
    NodeNotEmpty,
    NodeNotFound,
    NodePortInUse,
    NodePortOutOfRange,
    NodePortRangeExhausted,
    NodeRuntimeFailed,
    NodeRuntimeUnavailable,
    NodeState,
)
from rtsp_proxy.operator_access import OperatorPrincipal, OperatorRequestAuditContext


def node_dashboard_router(
    *,
    node_control: NodeControl | None,
    settings: Settings,
) -> APIRouter:
    """Build bounded create and non-disruptive node dashboard commands."""

    router = APIRouter()

    @router.get(
        "/dashboard/nodes/new",
        response_class=HTMLResponse,
        include_in_schema=False,
    )
    def node_create_page(request: Request) -> Response:
        principal = _principal(request)
        if isinstance(principal, Response):
            return principal
        if node_control is None:
            return _control_unavailable(principal)
        csrf_token = request.cookies.get("__Host-rtsp_proxy_csrf", "")
        if not 43 <= len(csrf_token) <= 1024:
            return _unavailable_response(
                DashboardUnavailable(
                    title="Требуется новая сессия",
                    message="CSRF cookie отсутствует или повреждён. Выполните вход повторно.",
                ),
                status_code=status.HTTP_401_UNAUTHORIZED,
                principal=principal,
            )
        return _html_response(
            render_node_create(
                principal=principal,
                csrf_token=csrf_token,
                port_range_start=settings.node_port_range_start,
                port_range_end=settings.node_port_range_end,
                idempotency_key=uuid4(),
            )
        )

    @router.post("/dashboard/nodes", include_in_schema=False)
    def create_node(request: Request) -> Response:
        principal = _principal(request)
        if isinstance(principal, Response):
            return principal
        if node_control is None:
            return _control_unavailable(principal)
        try:
            form = _form(request)
            form.require_exact_fields(
                frozenset({"_csrf", "name", "external_port", "idempotency_key"})
            )
            name = form.required("name", max_length=128)
            external_port = _optional_port(form)
            idempotency_key = _idempotency_key(form)
            node = node_control.register_node(
                name=name,
                port_range_start=settings.node_port_range_start,
                port_range_end=settings.node_port_range_end,
                max_nodes=settings.max_nodes,
                external_port=external_port,
                reserved_ports=settings.node_port_reserved,
                api_ports=range(
                    settings.node_api_port_range_start,
                    settings.node_api_port_range_end + 1,
                ),
                metrics_ports=range(
                    settings.node_metrics_port_range_start,
                    settings.node_metrics_port_range_end + 1,
                ),
                release_id=settings.node_release_id,
                mediamtx_binary_sha256=settings.node_mediamtx_binary_sha256,
                mutation_context=node_mutation_context(
                    principal=principal,
                    audit_context=_audit_context(request),
                    idempotency_key=idempotency_key,
                ),
            )
        except DashboardFormInvalid:
            return _form_invalid(principal)
        except NodeRuntimeFailed as error:
            return _node_registration_redirect(error.node_id)
        except Exception as error:
            expected = _node_error(error, principal)
            if expected is not None:
                return expected
            raise
        return _node_registration_redirect(node.id)

    @router.get(
        "/dashboard/nodes/{node_id}/registered",
        response_class=HTMLResponse,
        include_in_schema=False,
    )
    def registered_node(request: Request, node_id: UUID) -> Response:
        principal = _principal(request)
        if isinstance(principal, Response):
            return principal
        if node_control is None:
            return _control_unavailable(principal)
        try:
            node = next(
                (candidate for candidate in node_control.list_nodes() if candidate.id == node_id),
                None,
            )
        except Exception:
            return _control_unavailable(principal)
        if node is None:
            return _node_error(NodeNotFound("node_not_found"), principal) or _control_unavailable(
                principal
            )
        return _html_response(render_node_registration(node=node, principal=principal))

    def node_action(
        request: Request,
        node_id: UUID,
        operation: Callable[
            [NodeControl, UUID, NodeCommandFence, NodeMutationContext],
            MediaNode | None,
        ],
        *,
        allowed_states: frozenset[NodeState],
        deleted: bool = False,
    ) -> Response:
        principal = _principal(request)
        if isinstance(principal, Response):
            return principal
        if node_control is None:
            return _control_unavailable(principal)
        try:
            form = _form(request)
            form.require_exact_fields(
                frozenset({"_csrf", "expected_revision", "expected_state"})
            )
            fence = _node_fence(form)
            command = operator_node_command(
                principal=principal,
                audit_context=_audit_context(request),
                expected_revision=fence.expected_revision,
                expected_state=fence.expected_state,
                allowed_states=allowed_states,
            )
            operation(
                node_control,
                node_id,
                command.fence,
                command.mutation_context,
            )
        except (DashboardFormInvalid, ValueError):
            return _form_invalid(principal)
        except Exception as error:
            expected = _node_error(error, principal)
            if expected is not None:
                return expected
            raise
        return _overview_redirect() if deleted else _node_redirect(node_id)

    @router.post("/dashboard/nodes/{node_id}/start", include_in_schema=False)
    def start_node(request: Request, node_id: UUID) -> Response:
        return node_action(
            request,
            node_id,
            lambda control, value, fence, context: control.start_node(
                value,
                fence=fence,
                mutation_context=context,
            ),
            allowed_states=frozenset({NodeState.STOPPED, NodeState.FAILED}),
        )

    @router.post("/dashboard/nodes/{node_id}/stop", include_in_schema=False)
    def stop_node(request: Request, node_id: UUID) -> Response:
        return node_action(
            request,
            node_id,
            lambda control, value, fence, context: control.stop_node(
                value,
                fence=fence,
                mutation_context=context,
            ),
            allowed_states=frozenset(
                {NodeState.RUNNING, NodeState.DRAINING, NodeState.MAINTENANCE}
            ),
        )

    @router.post("/dashboard/nodes/{node_id}/drain", include_in_schema=False)
    def drain_node(request: Request, node_id: UUID) -> Response:
        return node_action(
            request,
            node_id,
            lambda control, value, fence, context: control.set_administrative_state(
                value,
                NodeState.DRAINING,
                fence=fence,
                mutation_context=context,
            ),
            allowed_states=frozenset({NodeState.RUNNING}),
        )

    @router.post("/dashboard/nodes/{node_id}/maintenance", include_in_schema=False)
    def maintain_node(request: Request, node_id: UUID) -> Response:
        return node_action(
            request,
            node_id,
            lambda control, value, fence, context: control.set_administrative_state(
                value,
                NodeState.MAINTENANCE,
                fence=fence,
                mutation_context=context,
            ),
            allowed_states=frozenset({NodeState.DRAINING}),
        )

    @router.post("/dashboard/nodes/{node_id}/resume", include_in_schema=False)
    def resume_node(request: Request, node_id: UUID) -> Response:
        return node_action(
            request,
            node_id,
            lambda control, value, fence, context: control.set_administrative_state(
                value,
                NodeState.RUNNING,
                fence=fence,
                mutation_context=context,
            ),
            allowed_states=frozenset({NodeState.DRAINING, NodeState.MAINTENANCE}),
        )

    @router.post("/dashboard/nodes/{node_id}/delete", include_in_schema=False)
    def delete_node(request: Request, node_id: UUID) -> Response:
        return node_action(
            request,
            node_id,
            lambda control, value, fence, context: control.delete_node(
                value,
                fence=fence,
                mutation_context=context,
            ),
            allowed_states=frozenset({NodeState.STOPPED, NodeState.FAILED}),
            deleted=True,
        )

    return router


def _form(request: Request) -> DashboardForm:
    form = getattr(request.state, "dashboard_form", None)
    if not isinstance(form, DashboardForm):
        raise DashboardFormInvalid("dashboard_form_invalid")
    return form


def _optional_port(form: DashboardForm) -> int | None:
    raw_port = form.optional("external_port", max_length=5)
    if raw_port is None or raw_port == "":
        return None
    try:
        port = int(raw_port, 10)
    except ValueError:
        raise DashboardFormInvalid("dashboard_form_invalid") from None
    if not 1 <= port <= 65535:
        raise DashboardFormInvalid("dashboard_form_invalid")
    return port


def _idempotency_key(form: DashboardForm) -> UUID:
    raw_key = form.required("idempotency_key", max_length=36)
    try:
        key = UUID(raw_key)
    except ValueError:
        raise DashboardFormInvalid("dashboard_form_invalid") from None
    if key.version != 4 or str(key) != raw_key:
        raise DashboardFormInvalid("dashboard_form_invalid")
    return key


def _node_fence(form: DashboardForm) -> NodeCommandFence:
    raw_revision = form.required("expected_revision", max_length=19)
    raw_state = form.required("expected_state", max_length=32)
    try:
        revision = int(raw_revision, 10)
        state = NodeState(raw_state)
        fence = NodeCommandFence(
            expected_revision=revision,
            expected_state=state,
        )
    except (ValueError, TypeError):
        raise DashboardFormInvalid("dashboard_form_invalid") from None
    return fence


def _audit_context(request: Request) -> OperatorRequestAuditContext:
    audit_context = getattr(request.state, "operator_audit_context", None)
    if not isinstance(audit_context, OperatorRequestAuditContext):
        raise DashboardFormInvalid("dashboard_form_invalid")
    return audit_context


def _principal(request: Request) -> OperatorPrincipal | Response:
    principal = getattr(request.state, "operator_principal", None)
    if isinstance(principal, OperatorPrincipal):
        return principal
    return _unavailable_response(
        DashboardUnavailable(
            title="Сессии операторов не настроены",
            message="Дашборд закрыт до подключения авторизации операторов.",
        ),
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
    )


def _node_error(
    error: Exception,
    principal: OperatorPrincipal,
) -> HTMLResponse | None:
    if isinstance(error, NodePortRangeExhausted):
        return _unavailable_response(
            DashboardUnavailable(
                title="Нет свободных портов",
                message="нет свободных портов для регистрации новой ноды",
            ),
            status_code=status.HTTP_409_CONFLICT,
            principal=principal,
        )
    if isinstance(error, MaximumNodesReached):
        return _unavailable_response(
            DashboardUnavailable(
                title="Достигнут предел нод",
                message="Измените max_nodes или освободите существующую ноду.",
            ),
            status_code=status.HTTP_409_CONFLICT,
            principal=principal,
        )
    if isinstance(error, NodeManagementPortRangeExhausted):
        return _unavailable_response(
            DashboardUnavailable(
                title="Нет management-портов",
                message="Нет свободной пары loopback API/metrics портов.",
            ),
            status_code=status.HTTP_409_CONFLICT,
            principal=principal,
        )
    if isinstance(error, NodePortOutOfRange):
        return _unavailable_response(
            DashboardUnavailable(
                title="Порт вне диапазона",
                message="Выберите порт из настроенного диапазона нод.",
            ),
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            principal=principal,
        )
    if isinstance(error, NodePortInUse):
        return _unavailable_response(
            DashboardUnavailable(
                title="Порт уже занят",
                message="Выберите другой порт или автоматическое размещение.",
            ),
            status_code=status.HTTP_409_CONFLICT,
            principal=principal,
        )
    if isinstance(error, NodeNotFound):
        return _unavailable_response(
            DashboardUnavailable(
                title="Нода не найдена",
                message="Нода больше не существует в текущем реестре.",
            ),
            status_code=status.HTTP_404_NOT_FOUND,
            principal=principal,
        )
    if isinstance(error, NodeNotEmpty):
        return _unavailable_response(
            DashboardUnavailable(
                title="Нода не пуста",
                message="Сначала переместите или удалите все камеры этой ноды.",
            ),
            status_code=status.HTTP_409_CONFLICT,
            principal=principal,
        )
    if isinstance(error, NodeLifecycleBusy):
        return _unavailable_response(
            DashboardUnavailable(
                title="Нода занята другой операцией",
                message="Обновите состояние и повторите действие.",
            ),
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            principal=principal,
        )
    if isinstance(error, NodeLifecycleConflict):
        return _unavailable_response(
            DashboardUnavailable(
                title="Состояние ноды изменилось",
                message="Обновите страницу и повторите допустимое действие.",
            ),
            status_code=status.HTTP_409_CONFLICT,
            principal=principal,
        )
    if isinstance(error, (NodeRuntimeUnavailable, NodeRuntimeFailed)):
        return _control_unavailable(principal)
    return None


def _form_invalid(principal: OperatorPrincipal) -> HTMLResponse:
    return _unavailable_response(
        DashboardUnavailable(
            title="Некорректная форма",
            message="Поля действия повреждены или превышают допустимый размер.",
        ),
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        principal=principal,
    )


def _control_unavailable(principal: OperatorPrincipal) -> HTMLResponse:
    return _unavailable_response(
        DashboardUnavailable(
            title="Управление нодами недоступно",
            message="Безопасно выполнить это действие сейчас невозможно.",
        ),
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        principal=principal,
    )


def _node_redirect(node_id: UUID) -> RedirectResponse:
    return RedirectResponse(
        f"/dashboard/nodes/{node_id}",
        status_code=status.HTTP_303_SEE_OTHER,
        headers={"Cache-Control": "no-store"},
    )


def _node_registration_redirect(node_id: UUID) -> RedirectResponse:
    return RedirectResponse(
        f"/dashboard/nodes/{node_id}/registered",
        status_code=status.HTTP_303_SEE_OTHER,
        headers={"Cache-Control": "no-store"},
    )


def _overview_redirect() -> RedirectResponse:
    return RedirectResponse(
        "/dashboard",
        status_code=status.HTTP_303_SEE_OTHER,
        headers={"Cache-Control": "no-store"},
    )


def _html_response(content: str, *, status_code: int = status.HTTP_200_OK) -> HTMLResponse:
    return HTMLResponse(
        content,
        status_code=status_code,
        headers={
            "Cache-Control": "no-store",
            "Content-Security-Policy": DASHBOARD_CSP,
            "Referrer-Policy": "no-referrer",
            "X-Content-Type-Options": "nosniff",
        },
    )


def _unavailable_response(
    unavailable: DashboardUnavailable,
    *,
    status_code: int,
    principal: OperatorPrincipal | None = None,
) -> HTMLResponse:
    response = _html_response(
        render_unavailable(unavailable, principal=principal),
        status_code=status_code,
    )
    if status_code == status.HTTP_503_SERVICE_UNAVAILABLE:
        response.headers["Retry-After"] = "5"
    return response
