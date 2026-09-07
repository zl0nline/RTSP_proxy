from __future__ import annotations

import argparse
import base64
import getpass
import os
import sys
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import quote
from uuid import UUID, uuid4

from rtsp_proxy.operator_access import (
    OperatorAccount,
    OperatorIdentitySource,
    OperatorMutationContext,
    OperatorRequestAuditContext,
    OperatorRole,
)
from rtsp_proxy.operator_identity import (
    LocalOperatorCredentials,
    OidcLoginInvalid,
    OidcLoginUnavailable,
    PostgresLocalOperatorStore,
    read_operator_secret_file,
)


class LocalOperatorProvisionError(ValueError):
    """A local operator cannot be provisioned safely."""


def main(
    argv: Sequence[str] | None = None,
    *,
    password_reader: Callable[[str], str] = getpass.getpass,
) -> int:
    parser = argparse.ArgumentParser(prog="rtsp-proxy-local-operator")
    parser.add_argument("--account-id", type=UUID)
    parser.add_argument("--username", default="admin")
    parser.add_argument("--display-name", default="Local administrator")
    parser.add_argument(
        "--role",
        action="append",
        choices=("viewer", "operator", "admin", "auditor"),
    )
    parser.add_argument("--scope", action="append")
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument("--with-totp", action="store_true")
    actions.add_argument(
        "--rotate-password",
        action="store_true",
        help="rotate an existing local operator password and revoke all web sessions",
    )
    actions.add_argument(
        "--enroll-totp",
        action="store_true",
        help="enroll TOTP for an existing password-only operator and revoke all sessions",
    )
    parser.add_argument("--actor", default="system:local-bootstrap")
    parser.add_argument("--reason", default="initial local operator provisioning")
    arguments = parser.parse_args(argv)
    try:
        if arguments.rotate_password:
            account_id = rotate_password_from_environment(
                username=arguments.username,
                password_reader=password_reader,
            )
            print(f"rotated local operator {account_id}; all web sessions revoked")
            return 0
        if arguments.enroll_totp:
            account_id, _secret = enroll_totp_from_environment(
                username=arguments.username,
                password_reader=password_reader,
                secret_writer=lambda secret: print(
                    f"TOTP enrollment URI (shown once): "
                    f"{_totp_enrollment_uri(arguments.username, secret)}"
                ),
            )
            print(f"enrolled TOTP for local operator {account_id}; all web sessions revoked")
            return 0
        account_id, totp_secret = provision_from_environment(
            account_id=arguments.account_id or uuid4(),
            username=arguments.username,
            display_name=arguments.display_name,
            roles=frozenset(OperatorRole(role) for role in (arguments.role or ("admin",))),
            scopes=frozenset(arguments.scope or ("server:*",)),
            with_totp=arguments.with_totp,
            actor=arguments.actor,
            reason=arguments.reason,
            password_reader=password_reader,
        )
    except OidcLoginInvalid as error:
        operation = "TOTP enrollment" if arguments.enroll_totp else "password change"
        print(f"local operator {operation} failed: {error}", file=sys.stderr)
        return 1
    except ValueError as error:
        if not isinstance(error, LocalOperatorProvisionError) and str(error) != (
            "local_operator_password_policy_failed"
        ):
            raise
        print(f"local operator provisioning failed: {error}", file=sys.stderr)
        return 1
    except OidcLoginUnavailable as error:
        print(f"local operator provisioning failed: {error}", file=sys.stderr)
        return 1
    print(f"provisioned local operator {account_id} at revision 1")
    if totp_secret is not None:
        print(
            "TOTP enrollment URI (shown once): "
            f"{_totp_enrollment_uri(arguments.username, totp_secret)}"
        )
    return 0


def provision_from_environment(
    *,
    account_id: UUID,
    username: str,
    display_name: str,
    roles: frozenset[OperatorRole],
    scopes: frozenset[str],
    with_totp: bool,
    actor: str,
    reason: str,
    password_reader: Callable[[str], str] = getpass.getpass,
) -> tuple[UUID, bytes | None]:
    database_url = os.environ.get("RTSP_PROXY_DATABASE_URL", "")
    key_file_value = os.environ.get("RTSP_PROXY_LOCAL_AUTH_ENCRYPTION_KEY_FILE", "")
    if (
        not database_url
        or not key_file_value
        or not 1 <= len(username) <= 256
        or username.startswith("local:")
        or any(character.isspace() for character in username)
        or not 1 <= len(display_name) <= 256
        or not roles
        or OperatorRole.BREAK_GLASS in roles
        or not scopes
    ):
        raise LocalOperatorProvisionError("local_operator_configuration_invalid")
    password = password_reader("Local operator password: ")
    confirmation = password_reader("Repeat local operator password: ")
    if (
        not isinstance(password, str)
        or not 12 <= len(password) <= 1024
        or password != confirmation
    ):
        raise LocalOperatorProvisionError("local_operator_password_confirmation_failed")
    encryption_key = _read_key(Path(key_file_value))
    totp_secret = os.urandom(20) if with_totp else None
    store = PostgresLocalOperatorStore(database_url, encryption_key=encryption_key)
    try:
        store.provision(
            account=OperatorAccount(
                id=account_id,
                identity_source=OperatorIdentitySource.LOCAL,
                subject=f"local:{username}",
                display_name=display_name,
                roles=roles,
                scopes=scopes,
                authz_version=1,
                enabled=True,
            ),
            credentials=LocalOperatorCredentials(
                password_scrypt=LocalOperatorCredentials.hash_password(password),
                totp_secret=totp_secret,
            ),
            context=OperatorMutationContext(actor=actor, reason=reason),
        )
    finally:
        store.close()
    return account_id, totp_secret


def rotate_password_from_environment(
    *,
    username: str,
    password_reader: Callable[[str], str] = getpass.getpass,
) -> UUID:
    database_url = os.environ.get("RTSP_PROXY_DATABASE_URL", "")
    key_file_value = os.environ.get("RTSP_PROXY_LOCAL_AUTH_ENCRYPTION_KEY_FILE", "")
    if not database_url or not key_file_value:
        raise LocalOperatorProvisionError("local_operator_configuration_invalid")
    current_password = password_reader("Current local operator password: ")
    new_password = password_reader("New local operator password: ")
    confirmation = password_reader("Repeat new local operator password: ")
    totp = password_reader("Current TOTP code (leave empty if disabled): ")
    if new_password != confirmation:
        raise LocalOperatorProvisionError("local_operator_password_confirmation_failed")
    store = PostgresLocalOperatorStore(
        database_url,
        encryption_key=_read_key(Path(key_file_value)),
    )
    try:
        account_id = store.account_id_for_username(username)
        if account_id is None:
            raise LocalOperatorProvisionError("local_operator_account_not_found")
        store.change_password(
            account_id=account_id,
            current_password=current_password,
            new_password=new_password,
            totp=totp,
            current_session_id=None,
            context=OperatorRequestAuditContext.internal(
                action="operator.password_change",
                resource_scope="session:self",
                resource_type="session",
                resource_id="self",
            ),
            now=datetime.now(UTC),
        )
    finally:
        store.close()
    return account_id


def enroll_totp_from_environment(
    *,
    username: str,
    password_reader: Callable[[str], str] = getpass.getpass,
    secret_writer: Callable[[bytes], None] = lambda _secret: None,
) -> tuple[UUID, bytes]:
    database_url = os.environ.get("RTSP_PROXY_DATABASE_URL", "")
    key_file_value = os.environ.get("RTSP_PROXY_LOCAL_AUTH_ENCRYPTION_KEY_FILE", "")
    if not database_url or not key_file_value:
        raise LocalOperatorProvisionError("local_operator_configuration_invalid")
    current_password = password_reader("Current local operator password: ")
    totp_secret = os.urandom(20)
    secret_writer(totp_secret)
    totp = password_reader("Current code from the authenticator: ")
    store = PostgresLocalOperatorStore(
        database_url,
        encryption_key=_read_key(Path(key_file_value)),
    )
    try:
        account_id = store.account_id_for_username(username)
        if account_id is None:
            raise LocalOperatorProvisionError("local_operator_account_not_found")
        store.enroll_totp(
            account_id=account_id,
            current_password=current_password,
            totp_secret=totp_secret,
            totp=totp,
            context=OperatorRequestAuditContext.internal(
                action="operator.local_totp_enroll",
                resource_scope="server:*",
                resource_type="operator_account",
                resource_id=str(account_id),
            ),
            now=datetime.now(UTC),
        )
    finally:
        store.close()
    return account_id, totp_secret


def _totp_enrollment_uri(username: str, secret: bytes) -> str:
    label = quote(f"RTSP Proxy:{username}")
    issuer = quote("RTSP Proxy")
    encoded = base64.b32encode(secret).decode("ascii").rstrip("=")
    return f"otpauth://totp/{label}?secret={encoded}&issuer={issuer}"


def _read_key(path: Path) -> bytes:
    try:
        payload = read_operator_secret_file(
            path,
            trusted_owner_uid=os.geteuid(),
            maximum_bytes=256,
        )
        encoded = payload.rstrip(b"\n")
        decoded = base64.urlsafe_b64decode(encoded + b"=" * (-len(encoded) % 4))
    except Exception:
        raise LocalOperatorProvisionError("local_operator_key_file_unsafe") from None
    if len(decoded) != 32 or base64.urlsafe_b64encode(decoded).rstrip(b"=") != encoded.rstrip(b"="):
        raise LocalOperatorProvisionError("local_operator_key_invalid")
    return decoded
