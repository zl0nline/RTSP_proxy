from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from rtsp_proxy.nodes import (
    NodeCommandFence,
    NodeDisruptionConfirmationContext,
    NodeMutationContext,
    NodeState,
)
from rtsp_proxy.operator_access import OperatorPrincipal, OperatorRequestAuditContext


@dataclass(frozen=True, slots=True)
class OperatorNodeCommand:
    fence: NodeCommandFence
    mutation_context: NodeMutationContext


class OperatorRecentMfaRequired(RuntimeError):
    """A destructive node command needs a newly MFA-verified session."""


def node_disruption_confirmation_context(
    *,
    principal: OperatorPrincipal,
    max_age_seconds: int,
) -> NodeDisruptionConfirmationContext:
    verified_at = principal.mfa_verified_at
    if not principal.has_recent_mfa(max_age_seconds=max_age_seconds) or verified_at is None:
        raise OperatorRecentMfaRequired("operator_recent_mfa_required")
    return NodeDisruptionConfirmationContext(
        account_id=principal.account_id,
        session_id=principal.session_id,
        authz_version=principal.authz_version,
        mfa_verified_at_unix_ms=int(verified_at.timestamp() * 1000),
    )


def node_mutation_context(
    *,
    principal: OperatorPrincipal,
    audit_context: OperatorRequestAuditContext,
    idempotency_key: UUID | None = None,
) -> NodeMutationContext:
    """Translate the authenticated HTTP boundary into a redacted node event context."""

    return NodeMutationContext(
        actor_account_id=principal.account_id,
        actor_session_id=principal.session_id,
        identity_source=principal.identity_source.value,
        actor_subject=principal.subject,
        roles=tuple(sorted(role.value for role in principal.roles)),
        scopes=tuple(sorted(principal.scopes)),
        authz_version=principal.authz_version,
        request_id=audit_context.request_id,
        action=audit_context.action,
        http_method=audit_context.http_method,
        resource_scope=audit_context.resource_scope,
        resource_type=audit_context.resource_type,
        resource_id=audit_context.resource_id,
        source_ip_sha256=audit_context.source_ip_sha256,
        user_agent_sha256=audit_context.user_agent_sha256,
        idempotency_key=idempotency_key,
    )


def operator_node_command(
    *,
    principal: OperatorPrincipal,
    audit_context: OperatorRequestAuditContext,
    expected_revision: int,
    expected_state: NodeState,
    allowed_states: frozenset[NodeState],
) -> OperatorNodeCommand:
    if expected_state not in allowed_states:
        raise ValueError("node_command_source_state_invalid")
    return OperatorNodeCommand(
        fence=NodeCommandFence(
            expected_revision=expected_revision,
            expected_state=expected_state,
        ),
        mutation_context=node_mutation_context(
            principal=principal,
            audit_context=audit_context,
        ),
    )
