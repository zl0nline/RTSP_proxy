from __future__ import annotations

import argparse
import base64
import binascii
import getpass
import os
import re
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from uuid import UUID

from sqlalchemy.exc import SQLAlchemyError

from rtsp_proxy.operator_access import (
    OperatorAccount,
    OperatorIdentitySource,
    OperatorMutationContext,
    OperatorRole,
)
from rtsp_proxy.operator_identity import (
    BreakGlassCredentials,
    OidcLoginInvalid,
    OidcLoginUnavailable,
    PostgresBreakGlassStore,
    read_operator_secret_file,
)


class BreakGlassProvisionError(ValueError):
    """The emergency account cannot be provisioned without exposing secrets."""


def main(
    argv: Sequence[str] | None = None,
    *,
    password_reader: Callable[[str], str] = getpass.getpass,
) -> int:
    parser = argparse.ArgumentParser(prog="rtsp-proxy-break-glass")
    parser.add_argument("--account-id", required=True, type=UUID)
    parser.add_argument("--username", default="emergency-admin")
    parser.add_argument("--actor", required=True)
    parser.add_argument("--reason", required=True)
    arguments = parser.parse_args(argv)
    try:
        provision_from_environment(
            account_id=arguments.account_id,
            username=arguments.username,
            actor=arguments.actor,
            reason=arguments.reason,
            password_reader=password_reader,
        )
    except (BreakGlassProvisionError, OidcLoginInvalid, OidcLoginUnavailable) as error:
        print(f"break-glass provisioning failed: {error}", file=sys.stderr)
        return 1
    print(f"provisioned break-glass account {arguments.account_id}")
    return 0


def provision_from_environment(
    *,
    account_id: UUID,
    username: str,
    actor: str,
    reason: str,
    password_reader: Callable[[str], str] = getpass.getpass,
) -> None:
    database_url = os.environ.get("RTSP_PROXY_DATABASE_URL", "")
    key_file_value = os.environ.get("RTSP_PROXY_BREAK_GLASS_ENCRYPTION_KEY_FILE", "")
    totp_file_value = os.environ.get("RTSP_PROXY_BREAK_GLASS_TOTP_FILE", "")
    if (
        not database_url
        or not key_file_value
        or not totp_file_value
        or not 1 <= len(username) <= 256
        or username.startswith("local:")
        or any(character.isspace() for character in username)
    ):
        raise BreakGlassProvisionError("break_glass_configuration_invalid")
    password = password_reader("Break-glass password: ")
    confirmation = password_reader("Repeat break-glass password: ")
    if (
        not isinstance(password, str)
        or not 16 <= len(password) <= 1024
        or password != confirmation
    ):
        raise BreakGlassProvisionError("break_glass_password_confirmation_failed")
    encryption_key = _read_secret(
        Path(key_file_value),
        expected_bytes=32,
    )
    totp_secret = _read_secret(
        Path(totp_file_value),
        minimum_bytes=20,
    )
    try:
        context = OperatorMutationContext(actor=actor, reason=reason)
        store = PostgresBreakGlassStore(database_url, encryption_key=encryption_key)
    except (SQLAlchemyError, ValueError):
        raise BreakGlassProvisionError("break_glass_configuration_invalid") from None
    try:
        existing_account_id = store.existing_break_glass_account_id()
        if existing_account_id is not None and existing_account_id != account_id:
            raise OidcLoginInvalid("break_glass_account_conflict")
        store.provision(
            account=OperatorAccount(
                id=account_id,
                identity_source=OperatorIdentitySource.BREAK_GLASS,
                subject=f"local:{username}",
                display_name="Emergency administrator",
                roles=frozenset({OperatorRole.BREAK_GLASS}),
                scopes=frozenset({"server:*"}),
                authz_version=1,
                enabled=True,
            ),
            password_scrypt=BreakGlassCredentials.hash_password(password),
            totp_secret=totp_secret,
            context=context,
        )
    finally:
        store.close()


def _read_secret(
    path: Path,
    *,
    expected_bytes: int | None = None,
    minimum_bytes: int | None = None,
) -> bytes:
    try:
        payload = read_operator_secret_file(
            path,
            trusted_owner_uid=os.geteuid(),
            maximum_bytes=256,
        )
    except ValueError:
        raise BreakGlassProvisionError("break_glass_secret_file_unsafe") from None
    return _decode_secret(
        payload,
        expected_bytes=expected_bytes,
        minimum_bytes=minimum_bytes,
    )


def _decode_secret(
    payload: bytes,
    *,
    expected_bytes: int | None = None,
    minimum_bytes: int | None = None,
) -> bytes:
    canonical_payload = payload[:-1] if payload.endswith(b"\n") else payload
    if not canonical_payload or re.fullmatch(rb"[A-Za-z0-9_-]+={0,2}", canonical_payload) is None:
        raise BreakGlassProvisionError("break_glass_secret_invalid")
    try:
        decoded = base64.b64decode(
            canonical_payload + b"=" * (-len(canonical_payload) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (binascii.Error, ValueError, TypeError):
        raise BreakGlassProvisionError("break_glass_secret_invalid") from None
    if (
        base64.urlsafe_b64encode(decoded).rstrip(b"=") != canonical_payload.rstrip(b"=")
        or canonical_payload.count(b"=")
        not in {0, (4 - len(canonical_payload.rstrip(b"=")) % 4) % 4}
        or (expected_bytes is not None and len(decoded) != expected_bytes)
        or (minimum_bytes is not None and len(decoded) < minimum_bytes)
        or len(decoded) > 64
    ):
        raise BreakGlassProvisionError("break_glass_secret_invalid")
    return decoded
